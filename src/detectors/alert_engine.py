# src/detectors/alert_engine.py
# Real-time alert engine that monitors metrics and fires alerts
# Loads trained models and classifies every incoming data point

import numpy as np
import pandas as pd
import os
import json
from datetime import datetime
from collections import deque
from src.utils.logger import setup_logger
from src.detectors.anomaly_detector import AnomalyDetector
from config.settings import settings


logger = setup_logger("alert_engine")

# ─────────────────────────────────────────
# ALERT SEVERITY LEVELS
# ─────────────────────────────────────────

class AlertSeverity:
    LOW      = "LOW"       # score 0.3 - 0.5
    MEDIUM   = "MEDIUM"    # score 0.5 - 0.75
    HIGH     = "HIGH"      # score 0.75 - 0.9
    CRITICAL = "CRITICAL"  # score > 0.9

def get_severity(anomaly_score):
    """Returns severity level based on anomaly score."""
    if anomaly_score >= 0.9:
        return AlertSeverity.CRITICAL
    elif anomaly_score >= 0.75:
        return AlertSeverity.HIGH
    elif anomaly_score >= 0.5:
        return AlertSeverity.MEDIUM
    elif anomaly_score >= 0.3:
        return AlertSeverity.LOW
    else:
        return None  # Not an alert

def guess_attack_type(metrics):
    """
    Guesses the attack type from raw metric values.
    Rule-based classifier on top of ML detection.
    """
    cpu    = metrics.get("cpu_usage", 0)
    mem    = metrics.get("memory_usage", 0)
    net_in = metrics.get("network_in", 0)
    req    = metrics.get("request_rate", 0)
    err    = metrics.get("error_rate", 0)
    resp   = metrics.get("response_time", 0)
    conn   = metrics.get("active_connections", 0)

    # DoS: everything maxed out
    if cpu > 85 and mem > 80 and req > 40000 and conn > 7000:
        return "dos_attack"

    # Data poisoning: high error + slow response
    if err > 40 and resp > 4000:
        return "data_poisoning"

    # Log injection: network spike + connections
    if net_in > 4000 and conn > 4000:
        return "log_injection"

    # Model evasion: subtle elevation across metrics
    if 65 < cpu < 85 and 70 < mem < 90 and 4 < err < 20:
        return "model_evasion"

    # FGSM: slight perturbation, hard to classify
    return "fgsm_attack"


# ─────────────────────────────────────────
# ALERT CLASS
# ─────────────────────────────────────────

class Alert:
    """Represents a single alert event."""

    def __init__(self, metrics, anomaly_score, severity,
                 attack_type, if_flag, ae_flag, rec_error):
        self.id               = datetime.now().strftime("%Y%m%d%H%M%S%f")
        self.timestamp        = datetime.now().isoformat()
        self.metrics          = metrics
        self.anomaly_score    = round(anomaly_score, 4)
        self.severity         = severity
        self.attack_type      = attack_type
        self.isolation_forest = if_flag
        self.autoencoder      = ae_flag
        self.reconstruction_error = round(rec_error, 6)
        self.resolved         = False

    def to_dict(self):
        return {
            "id":                   self.id,
            "timestamp":            self.timestamp,
            "severity":             self.severity,
            "attack_type":          self.attack_type,
            "anomaly_score":        self.anomaly_score,
            "reconstruction_error": self.reconstruction_error,
            "isolation_forest_flag":self.isolation_forest,
            "autoencoder_flag":     self.autoencoder,
            "resolved":             self.resolved,
            "metrics":              self.metrics
        }

    def __repr__(self):
        return (f"[ALERT {self.severity}] {self.attack_type} | "
                f"score={self.anomaly_score} | {self.timestamp}")


# ─────────────────────────────────────────
# MAIN ALERT ENGINE
# ─────────────────────────────────────────

class AlertEngine:
    """
    Real-time alert engine.
    - Loads trained ML models
    - Analyzes incoming metrics
    - Fires alerts with severity levels
    - Maintains alert history
    - Tracks attack statistics
    """

    def __init__(self):
        # Load trained detector
        self.detector = AnomalyDetector()
        self.detector.load_models()

        # Alert storage
        self.alert_history  = []          # all alerts ever fired
        self.recent_alerts  = deque(maxlen=100)  # last 100 alerts
        self.alert_counts   = {           # count by severity
            AlertSeverity.LOW:      0,
            AlertSeverity.MEDIUM:   0,
            AlertSeverity.HIGH:     0,
            AlertSeverity.CRITICAL: 0
        }
        self.attack_counts  = {}          # count by attack type
        self.total_analyzed = 0           # total samples analyzed
        self.total_attacks  = 0           # total attacks detected
    

        # Alert log file
        self.alert_log_path = os.path.join(
            settings.LOGS_DIR, "alerts.json"
        )
        os.makedirs(settings.LOGS_DIR, exist_ok=True)

        logger.info("AlertEngine initialized and models loaded")

    # ─────────────────────────────────────────
    # CORE ANALYSIS
    # ─────────────────────────────────────────

    def analyze(self, metrics: dict):
        """
        Analyzes a single metrics sample.
        Returns alert if attack detected, None if normal.

        metrics: dict with keys matching FEATURE_COLUMNS
        """
        self.total_analyzed += 1
      
        # Run ML prediction
        result = self.detector.predict_single(metrics)

        is_attack     = result["is_attack"]
        anomaly_score = result["anomaly_score"]
        if_flag       = result["isolation_forest_flag"]
        ae_flag       = result["autoencoder_flag"]
        rec_error     = result["reconstruction_error"]

        # If attack detected
        if is_attack:
            self.total_attacks += 1
            severity    = get_severity(anomaly_score)
            attack_type = guess_attack_type(metrics)

            # Create alert
            alert = Alert(
                metrics       = metrics,
                anomaly_score = anomaly_score,
                severity      = severity,
                attack_type   = attack_type,
                if_flag       = if_flag,
                ae_flag       = ae_flag,
                rec_error     = rec_error
            )

            # Store alert
            self.alert_history.append(alert)
            self.recent_alerts.append(alert)

            # Update counters
            if severity:
                self.alert_counts[severity] += 1
            self.attack_counts[attack_type] = (
                self.attack_counts.get(attack_type, 0) + 1
            )

            # Log the alert
            self._log_alert(alert)

            logger.warning(
                f"ATTACK DETECTED | {attack_type} | "
                f"severity={severity} | score={anomaly_score:.4f}"
            )

            return alert

        return None  # Normal traffic

    def analyze_batch(self, df: pd.DataFrame):
        """
        Analyzes a batch of samples.
        Returns list of alerts fired.
        """
        logger.info(f"Analyzing batch of {len(df)} samples...")
        alerts = []

        for _, row in df.iterrows():
            metrics = {col: row[col] for col in settings.FEATURE_COLUMNS}
            alert = self.analyze(metrics)
            if alert:
                alerts.append(alert)

        logger.info(
            f"Batch complete | {len(alerts)} attacks "
            f"detected out of {len(df)} samples"
        )
        return alerts

    # ─────────────────────────────────────────
    # STATISTICS
    # ─────────────────────────────────────────

    def get_stats(self):
        """Returns current engine statistics."""
        detection_rate = (
            (self.total_attacks / self.total_analyzed * 100)
            if self.total_analyzed > 0 else 0
        )
        return {
            "total_analyzed":   self.total_analyzed,
            "total_attacks":    self.total_attacks,
            "total_normal":     self.total_analyzed - self.total_attacks,
            "detection_rate":   round(detection_rate, 2),
            "alert_counts":     self.alert_counts,
            "attack_counts":    self.attack_counts,
            "recent_alerts":    len(self.recent_alerts)
        }

    def get_recent_alerts(self, n=10):
        """Returns last n alerts as list of dicts."""
        alerts = list(self.recent_alerts)[-n:]
        return [a.to_dict() for a in reversed(alerts)]

    # ─────────────────────────────────────────
    # LOGGING
    # ─────────────────────────────────────────

    def _log_alert(self, alert: Alert):
        """Appends alert to JSON log file."""
        try:
            # Load existing log
            if os.path.exists(self.alert_log_path):
                with open(self.alert_log_path, "r") as f:
                    log_data = json.load(f)
            else:
                log_data = []

            # Append new alert
            log_data.append(alert.to_dict())

            # Save back
            with open(self.alert_log_path, "w") as f:
                json.dump(log_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to log alert: {e}")

    def clear_alerts(self):
        """Clears all alerts from memory."""
        self.alert_history.clear()
        self.recent_alerts.clear()
        self.alert_counts = {k: 0 for k in self.alert_counts}
        self.attack_counts = {}
        self.total_analyzed = 0
        self.total_attacks = 0
        logger.info("All alerts cleared")


# ─────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "C:\\Users\\ISHANT JHA\\aiops-platform")

    logger.info("Testing Alert Engine...")
    engine = AlertEngine()

    # Test 1: Normal sample
    print("\n--- TEST 1: Normal Traffic ---")
    normal_sample = {
        "cpu_usage": 42.0, "memory_usage": 55.0,
        "network_in": 480.0, "network_out": 290.0,
        "disk_read": 98.0, "disk_write": 78.0,
        "request_rate": 980.0, "error_rate": 0.4,
        "response_time": 195.0, "active_connections": 490.0
    }
    alert = engine.analyze(normal_sample)
    print("Alert fired:", alert)
    print("Expected: None (normal traffic)")

    # Test 2: DoS Attack
    print("\n--- TEST 2: DoS Attack ---")
    dos_sample = {
        "cpu_usage": 97.0, "memory_usage": 95.0,
        "network_in": 12000.0, "network_out": 9000.0,
        "disk_read": 100.0, "disk_write": 80.0,
        "request_rate": 80000.0, "error_rate": 75.0,
        "response_time": 25000.0, "active_connections": 12000.0
    }
    alert = engine.analyze(dos_sample)
    print("Alert fired:", alert)

    # Test 3: Data Poisoning
    print("\n--- TEST 3: Data Poisoning ---")
    poison_sample = {
        "cpu_usage": 98.0, "memory_usage": 94.0,
        "network_in": 510.0, "network_out": 310.0,
        "disk_read": 102.0, "disk_write": 82.0,
        "request_rate": 1020.0, "error_rate": 80.0,
        "response_time": 8000.0, "active_connections": 510.0
    }
    alert = engine.analyze(poison_sample)
    print("Alert fired:", alert)

    # Test 4: Batch analysis
    print("\n--- TEST 4: Batch Analysis ---")
    df = pd.read_csv(
        "C:\\Users\\ISHANT JHA\\aiops-platform\\data\\raw\\full_dataset.csv"
    )
    test_batch = df.sample(100, random_state=42)
    alerts = engine.analyze_batch(test_batch)

    # Print stats
    print("\n--- FINAL STATS ---")
    stats = engine.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    print("\n--- RECENT ALERTS (last 5) ---")
    for a in engine.get_recent_alerts(5):
        print(f"  [{a['severity']}] {a['attack_type']} | score={a['anomaly_score']}")

    print("\n[OK] Step 4 Complete!")
    print(f"Alert log saved to: logs/alerts.json")