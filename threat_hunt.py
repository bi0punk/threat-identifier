import logging
import math
import os
import re
import signal
import sys
import time
from pathlib import Path

import joblib
import pandas as pd
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("threat_hunt")

MODEL_PATH = os.getenv("MODEL_PATH", "attack_detection_model.pkl")

try:
    model = joblib.load(MODEL_PATH)
    log.info("Modelo cargado: %s", MODEL_PATH)
except Exception:
    log.exception("No se pudo cargar el modelo desde %s", MODEL_PATH)
    sys.exit(1)

feature_cols = joblib.load("feature_columns.pkl")

label_encoders = {}
for col in ["IP", "Method", "Endpoint"]:
    path = f"label_encoder_{col}.pkl"
    try:
        label_encoders[col] = joblib.load(path)
    except FileNotFoundError:
        log.error("Label encoder no encontrado: %s. Ejecute trainer.py primero.", path)
        sys.exit(1)


_ATTACK_PATTERNS = {
    "sqli": r"(?i)(union.*select|or\s+[\"']?\s*[\"']?\s*=|\bselect\b.*\bfrom\b|--[\s]|;\s*--|\binsert\b.*\binto\b)",
    "xss": r"(?i)(<script|alert\s*\(|onerror\s*=|onload\s*=|javascript\s*:|<\/?img|\bprompt\s*\()",
    "path_traversal": r"(\.\./|\.\.\%2f|/etc/passwd|/windows/win\.ini|%00|\.\.\%5c)",
    "cmd_injection": r"(\||;\s*(ls|cat|id|whoami|dir|type)|`[^`]+`|\$\([^)]+\))",
    "scanner": r"(?i)(w00tw00t|acunetix|nikto|nessus|sqlmap|nmap)",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    ep = df["Endpoint"].astype(str)
    df["endpoint_length"] = ep.apply(len)
    df["special_char_ratio"] = ep.apply(lambda x: sum(1 for c in x if c in "'\";|<>()%$") / max(len(x), 1))
    for name, pattern in _ATTACK_PATTERNS.items():
        df["has_" + name] = ep.apply(lambda x, p=pattern: int(bool(re.search(p, x))))
    df["entropy"] = ep.apply(shannon_entropy)
    return df


def _transform_with_unknown(encoder, values):
    known = set(encoder.classes_)
    return [encoder.transform([v])[0] if v in known else -1 for v in values]


def preprocesar_datos(nuevos_datos):
    df = nuevos_datos.copy()
    for col in ["IP", "Method", "Endpoint"]:
        le = label_encoders[col]
        df[col + "_enc"] = _transform_with_unknown(le, df[col].astype(str))
    df = extract_features(df)
    return df[feature_cols]


def hacer_predicciones(nuevos_datos):
    X = preprocesar_datos(nuevos_datos)
    predicciones = model.predict(X)
    probabilidades = model.predict_proba(X)
    return predicciones, probabilidades


_running = True


def _handle_signal(signum, frame):
    global _running
    log.info("Senal %s recibida. Deteniendo monitor...", signum)
    _running = False


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, file_path):
        self.file_path = str(Path(file_path).resolve())
        self.last_line_count = 0
        try:
            data = pd.read_csv(self.file_path)
            self.last_line_count = data.shape[0]
            log.info("Archivo inicial con %d lineas", self.last_line_count)
        except (FileNotFoundError, pd.errors.EmptyDataError):
            log.warning("Archivo %s no encontrado o vacio. Iniciando desde 0.", self.file_path)

    def on_modified(self, event):
        if not _running:
            return
        resolved = str(Path(event.src_path).resolve())
        if resolved != self.file_path:
            return
        self._process_new_lines()

    def _process_new_lines(self):
        try:
            datos = pd.read_csv(self.file_path)
            current = datos.shape[0]

            if current > self.last_line_count:
                new_data = datos.tail(current - self.last_line_count)
                log.info("Nuevas lineas detectadas: %d", len(new_data))

                predicciones, probabilidades = hacer_predicciones(new_data)

                for i, (pred, prob) in enumerate(zip(predicciones, probabilidades)):
                    pct = max(prob) * 100
                    estado = "ATAQUE" if pred == 1 else "Normal"
                    log.info(
                        "Linea %d: %s (Precision: %.2f%%)",
                        self.last_line_count + i + 1, estado, pct,
                    )

                self.last_line_count = current
            elif current < self.last_line_count:
                log.warning("Archivo rotado/truncado. Reiniciando conteo.")
                self.last_line_count = 0

        except pd.errors.EmptyDataError:
            log.warning("Archivo CSV vacio.")
        except Exception:
            log.exception("Error procesando nuevas lineas")


def monitor(file_path: str):
    handler = LogFileHandler(file_path)
    observer = Observer()
    watch_dir = str(Path(file_path).parent) or "."
    observer.schedule(handler, path=watch_dir, recursive=False)
    observer.start()
    log.info("Monitoreando %s via watchdog...", file_path)
    try:
        while _running:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    csv_file_path = os.getenv("CSV_FILE_PATH", "access_logs.csv")
    monitor(csv_file_path)
