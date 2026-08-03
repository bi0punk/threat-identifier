# Attack Detection System

[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E?logo=scikit-learn)](https://scikit-learn.org/)
[![CI](https://github.com/bi0punk/threat-identifier/actions/workflows/ci.yml/badge.svg)](https://github.com/bi0punk/threat-identifier/actions)

Sistema de detección de amenazas que usa Machine Learning para analizar logs de acceso y predecir si un evento es un ataque, con monitoreo en tiempo real vía watchdog.

## Contenido

- [Características](#características)
- [Stack](#stack)
- [Estructura](#estructura)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Tests](#tests)
- [Configuración](#configuración)
- [Datos](#datos)
- [Modelo](#detalles-del-modelo)
- [Limitaciones / Roadmap](#limitaciones--roadmap)
- [Licencia](#licencia)

## Características

- **Detección basada en payload**: analiza patrones de SQLi, XSS, path traversal, command injection y scanners
- **Detección en tiempo real**: monitorea archivos CSV de logs vía watchdog (eventos del filesystem, sin polling)
- **Modelo ML**: Random Forest Classifier con 11 features
- **Predicciones con confianza**: muestra el % de certeza por predicción
- **Entrenador incluido**: `trainer.py` para reentrenar con datos propios
- **Preprocesamiento automático**: LabelEncoder + features derivadas (entropía, caracteres especiales, patrones de ataque)

## Stack

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.11+ |
| ML | scikit-learn (Random Forest) |
| Procesamiento | pandas, joblib, numpy |
| Monitoreo | watchdog (eventos del filesystem) |
| Testing | pytest |

## Estructura

```
threat-identifier/
├── threat_hunt.py           # Monitor en tiempo real (watchdog)
├── trainer.py               # Entrenamiento del modelo
├── tests/
├── .env.example
├── .github/workflows/ci.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

Archivos generados por `trainer.py` (gitignored):
- `attack_detection_model.pkl` — modelo entrenado
- `label_encoder_IP.pkl`, `label_encoder_Method.pkl`, `label_encoder_Endpoint.pkl` — encoders
- `feature_columns.pkl` — orden de columnas para predicción

## Requisitos

- Python 3.11+
- pip

## Instalación

```bash
git clone https://github.com/bi0punk/threat-identifier.git
cd threat-identifier
pip install -r requirements.txt
```

## Uso

### Entrenar modelo

```bash
python trainer.py
```

Genera el modelo, label encoders y `feature_columns.pkl`. Requiere un archivo `data.csv` con columnas `IP,Timestamp,Method,Endpoint,Status`.

### Monitorear logs en tiempo real

```bash
python threat_hunt.py
```

Usa watchdog para detectar nuevas líneas en `access_logs.csv` sin polling.

### Ejemplo de salida

```
Monitoreando access_logs.csv... (Total de líneas iniciales: 100)
Nuevas líneas detectadas: 3
Línea 101: Normal (Precisión: 98.75%)
Línea 102: ATAQUE (Precisión: 89.30%)
Línea 103: Normal (Precisión: 96.12%)
```

## Tests

```bash
pip install pytest
pytest tests/ -v
```

## Configuración

Variables de entorno (ver `.env.example`):

| Variable | Default | Descripción |
|---|---|---|
| `CSV_FILE_PATH` | `access_logs.csv` | Ruta al archivo de logs a monitorear |
| `MODEL_PATH` | `attack_detection_model.pkl` | Ruta al modelo entrenado |

## Datos

El dataset `data.csv` (no incluido en el repo) debe contener registros históricos con columnas: `IP`, `Timestamp`, `Method`, `Endpoint`, `Status`.

## Detalles del modelo

### Etiquetado de ataques

El modelo etiqueta como ataque (`Attack=1`) cuando:
- El endpoint contiene patrones de SQLi, XSS, path traversal o command injection
- El endpoint contiene firmas de scanners conocidos
- El código de status es 401, 403, 429 (intentos de acceso no autorizado)
- El código de status es 404 (potencial escaneo de endpoints)

### Algoritmo

Random Forest Classifier con 100 estimadores.

### Features (11 en total)

| Feature | Tipo | Descripción |
|---|---|---|
| `IP_enc` | Categórica | IP de origen (LabelEncoded) |
| `Method_enc` | Categórica | Método HTTP (LabelEncoded) |
| `Endpoint_enc` | Categórica | Ruta solicitada (LabelEncoded) |
| `endpoint_length` | Numérica | Longitud del endpoint |
| `special_char_ratio` | Numérica | Proporción de caracteres especiales |
| `has_sqli` | Booleana | Contiene patrón SQL injection |
| `has_xss` | Booleana | Contiene patrón XSS |
| `has_path_traversal` | Booleana | Contiene patrón path traversal |
| `has_cmd_injection` | Booleana | Contiene patrón command injection |
| `is_scanner` | Booleana | Contiene firma de scanner |
| `entropy` | Numérica | Entropía de Shannon del endpoint |

## Limitaciones / Roadmap

- [x] Detección binaria (ataque / no ataque)
- [x] Monitoreo en tiempo real vía watchdog
- [x] Features de payload (SQLi, XSS, path traversal, etc.)
- [ ] Modelo multi-clase (tipo de ataque: XSS, SQLi, etc.)
- [ ] Integración con SIEM (splunk, elastic)
- [ ] Alertas por email/webhook
- [ ] Dashboard web con métricas en vivo
- [ ] Soporte para logs en formato JSON

## Licencia

MIT
