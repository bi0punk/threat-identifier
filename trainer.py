import math
import re
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

ATTACK_PATTERNS = {
    "sqli": r"(?i)(union.*select|or\s+[\"']?\s*[\"']?\s*=|\bselect\b.*\bfrom\b|--[\s]|;\s*--|\binsert\b.*\binto\b)",
    "xss": r"(?i)(<script|alert\s*\(|onerror\s*=|onload\s*=|javascript\s*:|<\/?img|\bprompt\s*\()",
    "path_traversal": r"(\.\./|\.\.\%2f|/etc/passwd|/windows/win\.ini|%00|\.\.\%5c)",
    "cmd_injection": r"(\||;\s*(ls|cat|id|whoami|dir|type)|`[^`]+`|\$\([^)]+\))",
    "scanner": r"(?i)(w00tw00t|acunetix|nikto|nessus|sqlmap|nmap)",
}


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "Endpoint" in df.columns:
        df["endpoint_length"] = df["Endpoint"].astype(str).apply(len)
        df["special_char_ratio"] = df["Endpoint"].astype(str).apply(
            lambda x: sum(1 for c in x if c in "'\";|<>()%$") / max(len(x), 1)
        )
        df["has_sqli"] = df["Endpoint"].astype(str).apply(
            lambda x: int(bool(re.search(ATTACK_PATTERNS["sqli"], x)))
        )
        df["has_xss"] = df["Endpoint"].astype(str).apply(
            lambda x: int(bool(re.search(ATTACK_PATTERNS["xss"], x)))
        )
        df["has_path_traversal"] = df["Endpoint"].astype(str).apply(
            lambda x: int(bool(re.search(ATTACK_PATTERNS["path_traversal"], x)))
        )
        df["has_cmd_injection"] = df["Endpoint"].astype(str).apply(
            lambda x: int(bool(re.search(ATTACK_PATTERNS["cmd_injection"], x)))
        )
        df["is_scanner"] = df["Endpoint"].astype(str).apply(
            lambda x: int(bool(re.search(ATTACK_PATTERNS["scanner"], x)))
        )
        df["entropy"] = df["Endpoint"].astype(str).apply(lambda x: shannon_entropy(x))
    return df


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def label_attack(row) -> int:
    if row["Status"] == 404:
        return 1
    if pd.notna(row["Endpoint"]):
        for pattern_name, pattern in ATTACK_PATTERNS.items():
            if re.search(pattern, str(row["Endpoint"])):
                return 1
    if row["Status"] in (401, 403, 429):
        return 1
    return 0


data = pd.read_csv("data.csv", names=["IP", "Timestamp", "Method", "Endpoint", "Status"])

data["Attack"] = data.apply(label_attack, axis=1)

data = extract_features(data)

le_ip = LabelEncoder()
data["IP_enc"] = le_ip.fit_transform(data["IP"])
le_method = LabelEncoder()
data["Method_enc"] = le_method.fit_transform(data["Method"])
le_endpoint = LabelEncoder()
data["Endpoint_enc"] = le_endpoint.fit_transform(data["Endpoint"].astype(str))

feature_cols = [
    "IP_enc", "Method_enc", "Endpoint_enc",
    "endpoint_length", "special_char_ratio",
    "has_sqli", "has_xss", "has_path_traversal",
    "has_cmd_injection", "is_scanner", "entropy",
]
X = data[feature_cols]
y = data["Attack"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("=== Classification Report ===")
print(classification_report(y_test, y_pred))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))
scores = cross_val_score(model, X, y, cv=5)
print(f"=== CV Score (5-fold): {scores.mean():.4f} +/- {scores.std():.4f}")

joblib.dump(model, "attack_detection_model.pkl")
joblib.dump(le_ip, "label_encoder_IP.pkl")
joblib.dump(le_method, "label_encoder_Method.pkl")
joblib.dump(le_endpoint, "label_encoder_Endpoint.pkl")
joblib.dump(feature_cols, "feature_columns.pkl")

print("Entrenamiento completado. Modelo, codificadores y features guardados.")
