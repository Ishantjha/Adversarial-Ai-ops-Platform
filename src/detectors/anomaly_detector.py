# src/detectors/anomaly_detector.py

import numpy as np
import pandas as pd
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow import keras
from src.utils.logger import setup_logger
from config.settings import settings

logger = setup_logger("anomaly_detector")

class AnomalyDetector:

    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.autoencoder = None
        self.threshold = None
        self.is_trained = False
        logger.info("AnomalyDetector initialized")

    def prepare_data(self, df):
        X = df[settings.FEATURE_COLUMNS].values
        X = np.nan_to_num(X)
        return X

    def get_normal_data(self, df):
        normal_df = df[df["label"] == "normal"]
        logger.info(f"Normal samples for training: {len(normal_df)}")
        return normal_df

    def build_isolation_forest(self):
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        logger.info("Isolation Forest model built")

    def train_isolation_forest(self, X_train):
        logger.info("Training Isolation Forest...")
        self.isolation_forest.fit(X_train)
        logger.info("[OK] Isolation Forest trained")

    def predict_isolation_forest(self, X):
        raw_pred = self.isolation_forest.predict(X)
        return np.where(raw_pred == 1, 0, 1)

    def build_autoencoder(self, input_dim):
        inputs = keras.Input(shape=(input_dim,))
        encoded = keras.layers.Dense(32, activation="relu")(inputs)
        encoded = keras.layers.Dropout(0.2)(encoded)
        encoded = keras.layers.Dense(16, activation="relu")(encoded)
        encoded = keras.layers.Dense(8, activation="relu")(encoded)
        decoded = keras.layers.Dense(16, activation="relu")(encoded)
        decoded = keras.layers.Dropout(0.2)(decoded)
        decoded = keras.layers.Dense(32, activation="relu")(decoded)
        outputs = keras.layers.Dense(input_dim, activation="linear")(decoded)
        self.autoencoder = keras.Model(inputs, outputs, name="autoencoder")
        self.autoencoder.compile(optimizer="adam", loss="mse")
        logger.info(f"Autoencoder built - Input dim: {input_dim}")

    def train_autoencoder(self, X_train):
        logger.info("Training Autoencoder...")
        history = self.autoencoder.fit(
            X_train, X_train,
            epochs=50,
            batch_size=32,
            validation_split=0.1,
            verbose=1,
            callbacks=[
                keras.callbacks.EarlyStopping(
                    monitor="val_loss",
                    patience=5,
                    restore_best_weights=True
                )
            ]
        )
        logger.info("[OK] Autoencoder training complete")
        return history

    def compute_reconstruction_error(self, X):
        X_pred = self.autoencoder.predict(X, verbose=0)
        mse = np.mean(np.power(X - X_pred, 2), axis=1)
        return mse

    def set_threshold(self, X_normal):
        errors = self.compute_reconstruction_error(X_normal)
        self.threshold = np.mean(errors) + 3 * np.std(errors)
        logger.info(f"Anomaly threshold set: {self.threshold:.6f}")

    def predict_autoencoder(self, X):
        errors = self.compute_reconstruction_error(X)
        return (errors > self.threshold).astype(int)

    def predict(self, X):
        if not self.is_trained:
            raise ValueError("Models not trained yet!")

        X_scaled = self.scaler.transform(X)
        if_pred = self.predict_isolation_forest(X_scaled)
        ae_pred = self.predict_autoencoder(X_scaled)
        ae_errors = self.compute_reconstruction_error(X_scaled)
        combined = np.maximum(if_pred, ae_pred)
        ae_score = np.clip(ae_errors / (self.threshold * 2), 0, 1)

        return {
            "predictions": combined,
            "isolation_forest": if_pred,
            "autoencoder": ae_pred,
            "anomaly_scores": ae_score,
            "reconstruction_errors": ae_errors
        }

    def predict_single(self, sample_dict):
        df = pd.DataFrame([sample_dict])
        X = df[settings.FEATURE_COLUMNS].values
        X = np.nan_to_num(X)
        result = self.predict(X)

        return {
            "is_attack": bool(result["predictions"][0]),
            "anomaly_score": float(result["anomaly_scores"][0]),
            "isolation_forest_flag": bool(result["isolation_forest"][0]),
            "autoencoder_flag": bool(result["autoencoder"][0]),
            "reconstruction_error": float(result["reconstruction_errors"][0])
        }

    def train(self, df):
        logger.info("="*40)
        logger.info("Starting full training pipeline...")

        normal_df = self.get_normal_data(df)
        X_normal = self.prepare_data(normal_df)
        X_normal_scaled = self.scaler.fit_transform(X_normal)
        logger.info("[OK] Scaler fitted on normal data")

        self.build_isolation_forest()
        self.train_isolation_forest(X_normal_scaled)

        input_dim = X_normal_scaled.shape[1]
        self.build_autoencoder(input_dim)
        self.train_autoencoder(X_normal_scaled)

        self.set_threshold(X_normal_scaled)

        self.is_trained = True
        logger.info("[OK] Full training pipeline complete!")
        logger.info("="*40)

    def evaluate(self, df):
        logger.info("Evaluating models...")
        X = self.prepare_data(df)
        y_true = (df["label"] == "attack").astype(int).values
        result = self.predict(X)
        y_pred = result["predictions"]

        print("\n" + "="*50)
        print("MODEL EVALUATION REPORT")
        print("="*50)
        print(classification_report(
            y_true, y_pred,
            target_names=["Normal", "Attack"]
        ))
        print("Confusion Matrix:")
        print(confusion_matrix(y_true, y_pred))
        print("="*50)
        return y_true, y_pred

    def save_models(self):
        os.makedirs(settings.MODELS_DIR, exist_ok=True)
        joblib.dump(
            self.isolation_forest,
            os.path.join(settings.MODELS_DIR, "isolation_forest.pkl")
        )
        joblib.dump(
            self.scaler,
            os.path.join(settings.MODELS_DIR, "scaler.pkl")
        )
        joblib.dump(
            self.threshold,
            os.path.join(settings.MODELS_DIR, "threshold.pkl")
        )
        self.autoencoder.save(
            os.path.join(settings.MODELS_DIR, "autoencoder.keras")
        )
        logger.info("[OK] All models saved to disk")

    def load_models(self):
        self.isolation_forest = joblib.load(
            os.path.join(settings.MODELS_DIR, "isolation_forest.pkl")
        )
        self.scaler = joblib.load(
            os.path.join(settings.MODELS_DIR, "scaler.pkl")
        )
        self.threshold = joblib.load(
            os.path.join(settings.MODELS_DIR, "threshold.pkl")
        )
        self.autoencoder = keras.models.load_model(
            os.path.join(settings.MODELS_DIR, "autoencoder.keras")
        )
        self.is_trained = True
        logger.info("[OK] All models loaded from disk")