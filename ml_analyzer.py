import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models
import pandas as pd
from sklearn.preprocessing import StandardScaler
import logging
import json
from datetime import datetime

class NetworkBehaviorAnalyzer:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.history = []
        self.initialize_model()
        # Provo të ngarkosh modelin, nëse dështon, fito scaler-in me të dhëna fillestare
        if not self.load_model():
            self.fit_scaler()

    def initialize_model(self):
        """Inicializo modelin e rrjetit nervor"""
        try:
            # Krijo një rrjet nervor të thjeshtë për zbulimin e anomalive
            self.model = models.Sequential([
                layers.Dense(64, activation='relu', input_shape=(10,)),
                layers.Dropout(0.2),
                layers.Dense(32, activation='relu'),
                layers.Dropout(0.2),
                layers.Dense(16, activation='relu'),
                layers.Dense(1, activation='sigmoid')
            ])

            self.model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            logging.info("Modeli i rrjetit nervor u inicializua me sukses")
        except Exception as e:
            logging.error(f"Gabim gjatë inicializimit të modelit: {e}")

    def extract_features(self, packet_data):
        """Nxjerr karakteristikat nga të dhënat e paketës për analizë"""
        try:
            features = np.array([
                packet_data.get('packet_size', 0),
                packet_data.get('protocol', 0),
                packet_data.get('src_port', 0),
                packet_data.get('dst_port', 0),
                packet_data.get('ttl', 0),
                packet_data.get('window_size', 0),
                packet_data.get('tcp_flags', 0),
                packet_data.get('time_delta', 0),
                packet_data.get('packet_rate', 0),
                packet_data.get('connection_duration', 0)
            ]).reshape(1, -1)
            
            return self.scaler.transform(features)
        except Exception as e:
            logging.error(f"Gabim gjatë nxjerrjes së karakteristikave: {e}")
            return None

    def analyze_behavior(self, packet_data):
        """Analizo sjelljen e rrjetit duke përdorur modelin ML"""
        try:
            features = self.extract_features(packet_data)
            if features is not None:
                prediction = self.model.predict(features)
                return float(prediction[0][0])
            return 0.5  # Vlera e paracaktuar nëse nxjerrja e karakteristikave dështon
        except Exception as e:
            logging.error(f"Gabim gjatë analizës së sjelljes: {e}")
            return 0.5

    def update_model(self, packet_data, is_suspicious):
        """Përditëso modelin me të dhëna të reja trajnimi"""
        try:
            features = self.extract_features(packet_data)
            if features is not None:
                # Shto në histori
                self.history.append({
                    'features': features.tolist(),
                    'is_suspicious': is_suspicious,
                    'timestamp': datetime.now().isoformat()
                })

                # Mbaj vetëm 1000 shembujt e fundit
                if len(self.history) > 1000:
                    self.history = self.history[-1000:]

                # Përgatit të dhënat e trajnimit
                X = np.array([h['features'] for h in self.history])
                y = np.array([h['is_suspicious'] for h in self.history])

                # Përditëso modelin
                self.model.fit(X, y, epochs=1, verbose=0)
                logging.info("Modeli u përditësua me sukses")
        except Exception as e:
            logging.error(f"Gabim gjatë përditësimit të modelit: {e}")

    def save_model(self, path='model'):
        """Ruaj modelin dhe scaler-in"""
        try:
            self.model.save(f'{path}_model')
            with open(f'{path}_scaler.json', 'w') as f:
                json.dump({
                    'scale_': self.scaler.scale_.tolist(),
                    'mean_': self.scaler.mean_.tolist(),
                    'var_': self.scaler.var_.tolist()
                }, f)
            logging.info("Modeli dhe scaler-i u ruajtën me sukses")
        except Exception as e:
            logging.error(f"Gabim gjatë ruajtjes së modelit: {e}")

    def load_model(self, path='model'):
        """Ngarko modelin dhe scaler-in"""
        try:
            self.model = models.load_model(f'{path}_model')
            with open(f'{path}_scaler.json', 'r') as f:
                scaler_data = json.load(f)
                self.scaler.scale_ = np.array(scaler_data['scale_'])
                self.scaler.mean_ = np.array(scaler_data['mean_'])
                self.scaler.var_ = np.array(scaler_data['var_'])
            logging.info("Modeli dhe scaler-i u ngarkuan me sukses")
            return True
        except Exception as e:
            logging.error(f"Gabim gjatë ngarkimit të modelit: {e}")
            self.initialize_model()
            return False

    def fit_scaler(self):
        """Fito scaler-in me të dhëna fillestare për të shmangur gabimet"""
        try:
            # Krijo të dhëna fillestare me vargje të arsyeshme për karakteristikat e rrjetit
            dummy_data = np.array([
                [100, 1, 1024, 80, 64, 65535, 0, 0.1, 10, 1],  # Shembull pakete 1
                [150, 2, 53, 53, 128, 0, 0, 0.2, 20, 2],       # Shembull pakete 2
                [200, 1, 443, 443, 32, 32768, 0, 0.3, 30, 3],  # Shembull pakete 3
                [300, 2, 123, 123, 64, 0, 0, 0.4, 40, 4],      # Shembull pakete 4
                [400, 1, 22, 22, 16, 16384, 0, 0.5, 50, 5]     # Shembull pakete 5
            ])
            self.scaler.fit(dummy_data)
            logging.info("Scaler-i u fitua me të dhëna fillestare")
            # Krijo dhe ruaj modelin fillestar
            self.create_initial_model(dummy_data)
        except Exception as e:
            logging.error(f"Gabim gjatë fitimit të scaler-it: {e}")

    def create_initial_model(self, dummy_data):
        """Krijo dhe ruaj modelin fillestar me të dhëna trajnimi"""
        try:
            # Krijo më shumë të dhëna trajnimi me modele normale dhe të dyshimta
            normal_data = np.array([
                [100, 1, 1024, 80, 64, 65535, 0, 0.1, 10, 1],    # HTTP normal
                [150, 2, 53, 53, 128, 0, 0, 0.2, 20, 2],         # DNS normal
                [200, 1, 443, 443, 32, 32768, 0, 0.3, 30, 3],    # HTTPS normal
                [300, 2, 123, 123, 64, 0, 0, 0.4, 40, 4],        # NTP normal
                [400, 1, 22, 22, 16, 16384, 0, 0.5, 50, 5]       # SSH normal
            ])

            suspicious_data = np.array([
                [1000, 1, 1024, 22, 1, 0, 0, 0.01, 1000, 0.1],   # Skanim i dyshimtë SSH
                [2000, 1, 1024, 3389, 1, 0, 0, 0.01, 2000, 0.1], # Skanim i dyshimtë RDP
                [1500, 1, 1024, 445, 1, 0, 0, 0.01, 1500, 0.1],  # Skanim i dyshimtë SMB
                [3000, 1, 1024, 1433, 1, 0, 0, 0.01, 3000, 0.1], # Skanim i dyshimtë SQL
                [2500, 1, 1024, 3306, 1, 0, 0, 0.01, 2500, 0.1]  # Skanim i dyshimtë MySQL
            ])

            # Kombino dhe normalizo të dhënat
            X = np.vstack([normal_data, suspicious_data])
            y = np.array([0] * len(normal_data) + [1] * len(suspicious_data))  # 0 për normal, 1 për të dyshimtë

            # Normalizo karakteristikat
            X_normalized = self.scaler.fit_transform(X)

            # Trajno modelin
            self.model.fit(X_normalized, y, epochs=50, batch_size=2, verbose=0)

            # Ruaj modelin dhe scaler-in
            self.save_model()

            logging.info("Modeli fillestar u krijua dhe u ruajt me sukses")
        except Exception as e:
            logging.error(f"Gabim gjatë krijimit të modelit fillestar: {e}") 