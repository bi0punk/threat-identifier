import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
import time
import os

model = joblib.load('attack_detection_model.pkl')

# Inicializar el codificador
label_encoders = {}

def preprocesar_datos(nuevos_datos):
    for col in ['IP', 'Method', 'Endpoint']:
        le = LabelEncoder()
        nuevos_datos[col] = le.fit_transform(nuevos_datos[col].astype(str))
        label_encoders[col] = le  # Guardar el encoder para el futuro
    return nuevos_datos

def hacer_predicciones(nuevos_datos):
    nuevos_datos = preprocesar_datos(nuevos_datos)
    nuevos_datos = nuevos_datos.drop(columns=['Status', 'Timestamp'], errors='ignore')
    predicciones = model.predict(nuevos_datos)
    probabilidades = model.predict_proba(nuevos_datos)
    return predicciones, probabilidades


def monitor_csv(file_path, last_line_count):
    while True:
        datos_nuevos = pd.read_csv(file_path)
        current_line_count = datos_nuevos.shape[0]


        if current_line_count > last_line_count:
            # Obtener las nuevas líneas
            ultimos_datos = datos_nuevos.tail(current_line_count - last_line_count)
            print("Columnas de los últimos datos:", ultimos_datos.columns)

            # Realiza las predicciones
            predicciones, probabilidades = hacer_predicciones(ultimos_datos)

            # Imprimir los resultados
            for i, (prediccion, probabilidad) in enumerate(zip(predicciones, probabilidades)):
                porcentaje_certeza = max(probabilidad) * 100
                estado = "Ataque" if prediccion == 1 else "No Ataque"
                print(f"Línea {last_line_count + i + 1}: {estado} (Precisión: {porcentaje_certeza:.2f}%)")
            
            # Actualizar el número de líneas leídas
            last_line_count = current_line_countbar
        time.sleep(5)

if __name__ == "__main__":
    # Ruta del archivo CSV
    csv_file_path = 'access_logs.csv'


    initial_data = pd.read_csv(csv_file_path)
    line_count = initial_data.shape[0]

    print(f"Monitoreando {csv_file_path}... (Total de líneas iniciales: {line_count})")
    
    # Comenzar a monitorear el archivo CSV
    monitor_csv(csv_file_path, line_count)
