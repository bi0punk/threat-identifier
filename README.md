# Attack Detection System

[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E?logo=scikit-learn)](https://scikit-learn.org/)
[![CI](https://github.com/drbash/threat-identifier/actions/workflows/ci.yml/badge.svg)](https://github.com/drbash/threat-identifier/actions)

Sistema de detección de amenazas que usa Machine Learning para analizar logs de acceso (`access_logs.csv`) y predecir si un evento es un ataque, con monitoreo en tiempo real.

## Contenido

- [Características](#caracter%C3%ADsticas)
- [Stack](#stack)
- [Estructura](#estructura)
- [Requisitos](#requisitos)
- [Instalación](#instalaci%C3%B3n)
- [Uso](#uso)
- [Tests](#tests)
- [Configuración](#configuraci%C3%B3n)
- [CI/CD](#cicd)
- [Datos](#datos)
- [Modelo](#detalles-del-modelo)
- [Personalización](#personalizaci%C3%B3n)
- [Limitaciones / Roadmap](#limitaciones--roadmap)
- [Licencia](#licencia)

## Características

- **Detección en tiempo real**: monitorea continuamente el archivo CSV de logs
- **Modelo ML**: Random Forest Classifier preentrenado
- **Predicciones con confianza**: muestra el % de certeza por predicción
- **Entrenador incluido**: `trainer.py` para reentrenar con datos propios
- **Preprocesamiento automático**: codificación de IP, Method y Endpoint vía LabelEncoder

## Stack

| Componente | Tecnología |
|---|---|
| Lenguaje | Python 3.11+ |
| ML | scikit-learn (Random Forest) |
| Procesamiento | pandas, joblib |
| Testing | pytest |

## Estructura

```
threat-identifier/
├── threat_hunt.py                   # Monitor en tiempo real
├── trainer.py                       # Entrenamiento del modelo
├── attack_detection_model.pkl       # Modelo preentrenado
├── data.csv                         # Dataset de entrenamiento
├── access_logs.csv                  # Logs a analizar (ejemplo)
├── tests/
├── .env.example
├── .github/workflows/ci.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Requisitos

- Python 3.11+
- pip

## Instalación

```bash
git clone https://github.com/drbash/threat-identifier.git
cd threat-identifier
pip install -r requirements.txt
```

Asegúrate de que `attack_detection_model.pkl` esté en el directorio raíz.

## Uso

### Entrenar modelo

```bash
python trainer.py
```

Esto genera `attack_detection_model.pkl` y los label encoders.

### Monitorear logs en tiempo real

```bash
python threat_hunt.py
```

### Ejemplo de salida

```plaintext
Monitoreando access_logs.csv... (Total de líneas iniciales: 100)
Columnas de los últimos datos: ['IP', 'Method', 'Endpoint', 'Status', 'Timestamp']
Línea 101: No Ataque (Precisión: 96.75%)
Línea 102: Ataque (Precisión: 89.30%)
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
| `CSV_FILE` | `access_logs.csv` | Ruta al archivo de logs |

## CI/CD

GitHub Actions ejecuta lint (Ruff) y tests (pytest) en cada push/PR.

## Datos

El dataset `data.csv` contiene registros históricos con columnas: `IP`, `Timestamp`, `Method`, `Endpoint`, `Status`. El modelo etiqueta como ataque (`Attack=1`) cuando `Status=404`.

## Detalles del modelo

### Algoritmo

Random Forest Classifier con 100 estimadores.

### Preprocesamiento

- **Codificación**: `IP`, `Method`, `Endpoint` → LabelEncoder
- **Características ignoradas**: `Status`, `Timestamp`

### Features usadas

- `IP` (origen)
- `Method` (GET, POST, etc.)
- `Endpoint` (ruta solicitada)

## Personalización

- **CSV propio**: cambia la ruta en `threat_hunt.py` (variable `csv_file_path`)
- **Modelo propio**: reemplaza `attack_detection_model.pkl` por tu modelo entrenado
- **Hiperparámetros**: modifica `trainer.py` (n_estimators, test_size, etc.)

## Limitaciones / Roadmap

- [x] Detección binaria (ataque / no ataque)
- [x] Monitoreo en tiempo real de CSV
- [ ] Modelo multi-clase (tipo de ataque: XSS, SQLi, etc.)
- [ ] Integración con SIEM (splunk, elastic)
- [ ] Alertas por email/webhook
- [ ] Dashboard web con métricas en vivo
- [ ] Soporte para logs en formato JSON

## Licencia

MIT
