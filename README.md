# README.md

# Attack Detection System

Este proyecto es un sistema de detección de ataques que utiliza un modelo de machine learning para analizar registros de acceso (`access_logs.csv`) y predecir si un evento registrado es un ataque o no. El sistema monitorea continuamente un archivo CSV, analiza los nuevos registros y predice el estado de cada uno, indicando la probabilidad de que sea un ataque.

---

## Requisitos del sistema

Antes de comenzar, asegúrate de tener instalado lo siguiente:

- Python 3.8 o superior
- Bibliotecas requeridas (instalables con `pip install -r requirements.txt`):
  - pandas
  - joblib
  - scikit-learn

---

## Estructura del proyecto

```
├── attack_detection_model.pkl  # Modelo preentrenado
├── access_logs.csv             # Archivo CSV con los registros a analizar
├── main.py                     # Código fuente principal
├── README.md                   # Documento de descripción del proyecto
├── requirements.txt            # Dependencias del proyecto
```

---

## Instalación

1. **Clonar el repositorio**  
   Clona el repositorio en tu máquina local:
   ```bash
   git clone https://github.com/tu-usuario/attack-detection.git
   cd attack-detection
   ```

2. **Instalar las dependencias**  
   Ejecuta el siguiente comando para instalar todas las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

3. **Asegurar el modelo preentrenado**  
   Asegúrate de que el archivo `attack_detection_model.pkl` esté ubicado en el directorio raíz del proyecto.

4. **Agregar el archivo CSV**  
   Coloca el archivo `access_logs.csv` con tus registros en el directorio raíz.

---

## Uso

1. **Ejecutar el sistema de monitoreo**  
   Inicia el script principal con el siguiente comando:
   ```bash
   python main.py
   ```

2. **Monitoreo en tiempo real**  
   El script comenzará a monitorear el archivo `access_logs.csv` en busca de nuevas líneas. Cuando detecte nuevos registros, preprocesará los datos y hará predicciones, indicando si representan un ataque y con qué nivel de confianza.

---

## Ejemplo de salida

Al ejecutarse, el script produce una salida similar a esta:

```plaintext
Monitoreando access_logs.csv... (Total de líneas iniciales: 100)
Columnas de los últimos datos: ['IP', 'Method', 'Endpoint', 'Status', 'Timestamp']
Línea 101: No Ataque (Precisión: 96.75%)
Línea 102: Ataque (Precisión: 89.30%)
```

---

## Detalles del modelo

El modelo `attack_detection_model.pkl` es un clasificador preentrenado basado en técnicas de machine learning. Este utiliza las columnas `IP`, `Method`, y `Endpoint` como características para predecir si un evento es un ataque.

### Preprocesamiento
- **Codificación**: Las columnas `IP`, `Method` y `Endpoint` se convierten a valores numéricos usando `LabelEncoder` de scikit-learn.
- **Características ignoradas**: Las columnas `Status` y `Timestamp` no se utilizan en el modelo.

---

## Personalización

- **Archivo CSV**: Si deseas usar otro archivo CSV, actualiza la ruta en el script `main.py` en la variable `csv_file_path`.
- **Modelo personalizado**: Si tienes otro modelo, reemplaza `attack_detection_model.pkl` con tu modelo y asegúrate de que acepte las mismas características.


---

## Licencia

Este proyecto está bajo la [Licencia MIT](https://opensource.org/licenses/MIT).
