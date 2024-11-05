import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# Cargar los datos del CSV
data = pd.read_csv('data.csv', names=['IP', 'Timestamp', 'Method', 'Endpoint', 'Status'])

# Crear una columna de 'Intento de ataque' basado en la condición de status 404 como ejemplo
data['Attack'] = data['Status'].apply(lambda x: 1 if x == 404 else 0)

# Preprocesamiento: codificación de variables categóricas
le_ip = LabelEncoder()
data['IP'] = le_ip.fit_transform(data['IP'])

le_method = LabelEncoder()
data['Method'] = le_method.fit_transform(data['Method'])

le_endpoint = LabelEncoder()
data['Endpoint'] = le_endpoint.fit_transform(data['Endpoint'])

# Seleccionar las características y la etiqueta
X = data[['IP', 'Method', 'Endpoint']]
y = data['Attack']

# Dividir los datos en entrenamiento y prueba
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Entrenar el modelo de Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predecir y evaluar el modelo
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Guardar el modelo si es necesario
import joblib
joblib.dump(model, 'attack_detection_model.pkl')

print("Entrenamiento completado y modelo guardado.")
