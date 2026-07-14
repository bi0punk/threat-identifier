import pandas as pd
import joblib
import time
import os
import signal
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("threat_hunt")

model = joblib.load('attack_detection_model.pkl')

label_encoders = {}
for col in ['IP', 'Method', 'Endpoint']:
    label_encoders[col] = joblib.load(f'label_encoder_{col}.pkl')

_running = True

def _handle_signal(signum, frame):
    global _running
    log.info(f"Señal {signum} recibida. Deteniendo monitor...")
    _running = False

signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

def _transform_with_unknown(encoder, values):
    known = set(encoder.classes_)
    return [encoder.transform([v])[0] if v in known else -1 for v in values]

def preprocesar_datos(nuevos_datos):
    for col in ['IP', 'Method', 'Endpoint']:
        le = label_encoders[col]
        nuevos_datos[col] = _transform_with_unknown(le, nuevos_datos[col].astype(str))
    return nuevos_datos

def hacer_predicciones(nuevos_datos):
    nuevos_datos = preprocesar_datos(nuevos_datos)
    nuevos_datos = nuevos_datos.drop(columns=['Status', 'Timestamp'], errors='ignore')
    predicciones = model.predict(nuevos_datos)
    probabilidades = model.predict_proba(nuevos_datos)
    return predicciones, probabilidades


def monitor_csv(file_path, last_line_count):
    global _running
    while _running:
        try:
            if not Path(file_path).exists():
                log.warning(f"Archivo {file_path} no encontrado. Esperando...")
                time.sleep(5)
                continue

            datos_nuevos = pd.read_csv(file_path)
            current_line_count = datos_nuevos.shape[0]

            if current_line_count > last_line_count:
                ultimos_datos = datos_nuevos.tail(current_line_count - last_line_count)
                log.info("Nuevas líneas detectadas: %d", len(ultimos_datos))

                predicciones, probabilidades = hacer_predicciones(ultimos_datos)

                for i, (prediccion, probabilidad) in enumerate(zip(predicciones, probabilidades)):
                    porcentaje_certeza = max(probabilidad) * 100
                    estado = "Ataque" if prediccion == 1 else "No Ataque"
                    log.info("Línea %d: %s (Precisión: %.2f%%)", last_line_count + i + 1, estado, porcentaje_certeza)

                last_line_count = current_line_count
            elif current_line_count < last_line_count:
                log.warning("El archivo fue rotado/truncado. Reiniciando conteo.")
                last_line_count = 0
        except pd.errors.EmptyDataError:
            log.warning("Archivo CSV vacío. Esperando...")
        except Exception as e:
            log.error("Error en el monitoreo: %s", e)
        time.sleep(5)

if __name__ == "__main__":
    csv_file_path = os.getenv("CSV_FILE_PATH", "access_logs.csv")

    try:
        initial_data = pd.read_csv(csv_file_path)
        line_count = initial_data.shape[0]
    except (FileNotFoundError, pd.errors.EmptyDataError):
        line_count = 0
        log.warning("Archivo inicial %s no encontrado o vacío. Iniciando desde 0.", csv_file_path)

    log.info("Monitoreando %s... (Total de líneas iniciales: %d)", csv_file_path, line_count)
    monitor_csv(csv_file_path, line_count)
