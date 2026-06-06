# src/utils/data_simulator.py
# Generates realistic cloud infrastructure metrics
# Both normal behavior and various attack patterns

import numpy as np
import pandas as pd
import os
import json
from datetime import datetime, timedelta
from src.utils.logger import setup_logger
from config.settings import settings

logger = setup_logger("data_simulator")

class DataSimulator:
    """
    Simulates cloud infrastructure metrics.
    Generates normal traffic + 5 types of adversarial attacks.
    """

    def __init__(self):
        # Set random seed for reproducibility
        np.random.seed(42)
        logger.info("DataSimulator initialized")

    # ─────────────────────────────────────────
    # NORMAL DATA GENERATION
    # ─────────────────────────────────────────

    def generate_normal_sample(self):
        """
        Generates ONE sample of normal cloud metrics.
        Values are realistic ranges for a healthy system.
        """
        return {
            "cpu_usage":          np.random.normal(40, 10),     # avg 40%, std 10%
            "memory_usage":       np.random.normal(55, 8),      # avg 55%, std 8%
            "network_in":         np.random.normal(500, 100),   # MB/s
            "network_out":        np.random.normal(300, 80),    # MB/s
            "disk_read":          np.random.normal(100, 20),    # MB/s
            "disk_write":         np.random.normal(80, 15),     # MB/s
            "request_rate":       np.random.normal(1000, 200),  # requests/sec
            "error_rate":         np.random.normal(0.5, 0.2),   # % errors
            "response_time":      np.random.normal(200, 50),    # milliseconds
            "active_connections": np.random.normal(500, 100),   # connections
        }

    def generate_normal_data(self, n_samples=1000):
        """Generates n_samples of normal data."""
        logger.info(f"Generating {n_samples} normal samples...")
        samples = []

        for i in range(n_samples):
            sample = self.generate_normal_sample()
            # Clip values to realistic ranges (no negatives)
            sample = {k: max(0, v) for k, v in sample.items()}
            sample["label"] = "normal"
            sample["attack_type"] = "none"
            sample["timestamp"] = (
                datetime.now() - timedelta(seconds=n_samples - i)
            ).isoformat()
            samples.append(sample)

        logger.info(f"[OK] Normal data generated: {n_samples} samples")
        return pd.DataFrame(samples)

    # ─────────────────────────────────────────
    # ATTACK DATA GENERATION
    # ─────────────────────────────────────────

    def generate_fgsm_attack(self, n_samples=200):
        """
        FGSM (Fast Gradient Sign Method) Attack.
        Adds small crafted perturbations to fool ML models.
        Metrics look almost normal but slightly shifted.
        """
        logger.info(f"Generating {n_samples} FGSM attack samples...")
        samples = []
        epsilon = 0.3  # perturbation strength

        for i in range(n_samples):
            base = self.generate_normal_sample()
            # Add adversarial perturbation to each feature
            attacked = {
                k: v + epsilon * np.random.choice([-1, 1]) * abs(v) * 0.2
                for k, v in base.items()
            }
            attacked = {k: max(0, v) for k, v in attacked.items()}
            attacked["label"] = "attack"
            attacked["attack_type"] = "fgsm_attack"
            attacked["timestamp"] = (
                datetime.now() - timedelta(seconds=n_samples - i)
            ).isoformat()
            samples.append(attacked)

        logger.info(f"[OK] FGSM attack data generated: {n_samples} samples")
        return pd.DataFrame(samples)

    def generate_data_poisoning(self, n_samples=200):
        """
        Data Poisoning Attack.
        Injects corrupted data into the system to degrade model accuracy.
        Shows extreme/impossible metric values.
        """
        logger.info(f"Generating {n_samples} data poisoning samples...")
        samples = []

        for i in range(n_samples):
            base = self.generate_normal_sample()
            # Poison specific features with extreme values
            poisoned = base.copy()
            poisoned["cpu_usage"]    = np.random.uniform(95, 100)  # maxed out
            poisoned["memory_usage"] = np.random.uniform(90, 100)  # maxed out
            poisoned["error_rate"]   = np.random.uniform(50, 100)  # huge errors
            poisoned["response_time"]= np.random.uniform(5000, 10000) # very slow
            # Other features look normal (to evade detection)
            poisoned["label"] = "attack"
            poisoned["attack_type"] = "data_poisoning"
            poisoned["timestamp"] = (
                datetime.now() - timedelta(seconds=n_samples - i)
            ).isoformat()
            samples.append(poisoned)

        logger.info(f"[OK] Data poisoning samples generated: {n_samples} samples")
        return pd.DataFrame(samples)

    def generate_log_injection(self, n_samples=200):
        """
        Log Injection Attack.
        Attacker injects fake log entries to confuse monitoring.
        Network metrics go haywire while CPU looks normal.
        """
        logger.info(f"Generating {n_samples} log injection samples...")
        samples = []

        for i in range(n_samples):
            base = self.generate_normal_sample()
            injected = base.copy()
            # Sudden spike in network + connections
            injected["network_in"]         = np.random.uniform(5000, 10000)
            injected["network_out"]         = np.random.uniform(4000, 9000)
            injected["active_connections"]  = np.random.uniform(5000, 10000)
            injected["request_rate"]        = np.random.uniform(10000, 50000)
            injected["label"] = "attack"
            injected["attack_type"] = "log_injection"
            injected["timestamp"] = (
                datetime.now() - timedelta(seconds=n_samples - i)
            ).isoformat()
            samples.append(injected)

        logger.info(f"[OK] Log injection samples generated: {n_samples} samples")
        return pd.DataFrame(samples)

    def generate_model_evasion(self, n_samples=200):
        """
        Model Evasion Attack.
        Attacker knows our model and crafts inputs to evade detection.
        Metrics stay just within normal ranges but pattern is wrong.
        """
        logger.info(f"Generating {n_samples} model evasion samples...")
        samples = []

        for i in range(n_samples):
            base = self.generate_normal_sample()
            evaded = base.copy()
            # Subtle but consistent pattern shift
            evaded["cpu_usage"]     = np.random.uniform(70, 80)
            evaded["memory_usage"]  = np.random.uniform(75, 85)
            evaded["disk_read"]     = np.random.uniform(300, 500)
            evaded["disk_write"]    = np.random.uniform(250, 450)
            evaded["error_rate"]    = np.random.uniform(5, 15)
            evaded["label"] = "attack"
            evaded["attack_type"] = "model_evasion"
            evaded["timestamp"] = (
                datetime.now() - timedelta(seconds=n_samples - i)
            ).isoformat()
            samples.append(evaded)

        logger.info(f"[OK] Model evasion samples generated: {n_samples} samples")
        return pd.DataFrame(samples)

    def generate_dos_attack(self, n_samples=200):
        """
        DoS (Denial of Service) Attack.
        Floods the system with requests causing resource exhaustion.
        Everything spikes simultaneously.
        """
        logger.info(f"Generating {n_samples} DoS attack samples...")
        samples = []

        for i in range(n_samples):
            base = self.generate_normal_sample()
            dos = base.copy()
            # Everything maxed out simultaneously
            dos["cpu_usage"]          = np.random.uniform(90, 100)
            dos["memory_usage"]       = np.random.uniform(85, 100)
            dos["network_in"]         = np.random.uniform(8000, 15000)
            dos["network_out"]        = np.random.uniform(6000, 12000)
            dos["request_rate"]       = np.random.uniform(50000, 100000)
            dos["active_connections"] = np.random.uniform(8000, 15000)
            dos["response_time"]      = np.random.uniform(8000, 30000)
            dos["error_rate"]         = np.random.uniform(40, 90)
            dos["label"] = "attack"
            dos["attack_type"] = "dos_attack"
            dos["timestamp"] = (
                datetime.now() - timedelta(seconds=n_samples - i)
            ).isoformat()
            samples.append(dos)

        logger.info(f"[OK] DoS attack samples generated: {n_samples} samples")
        return pd.DataFrame(samples)

    # ─────────────────────────────────────────
    # COMBINED DATASET BUILDER
    # ─────────────────────────────────────────

    def generate_full_dataset(self, save=True):
        """
        Generates the complete dataset:
        1000 normal + 200 of each attack type = 2000 total samples.
        Shuffles and saves to CSV.
        """
        logger.info("Building full dataset...")

        # Generate all data
        normal_df    = self.generate_normal_data(1000)
        fgsm_df      = self.generate_fgsm_attack(200)
        poison_df    = self.generate_data_poisoning(200)
        injection_df = self.generate_log_injection(200)
        evasion_df   = self.generate_model_evasion(200)
        dos_df       = self.generate_dos_attack(200)

        # Combine all into one dataframe
        full_df = pd.concat([
            normal_df, fgsm_df, poison_df,
            injection_df, evasion_df, dos_df
        ], ignore_index=True)

        # Shuffle the dataset
        full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)

        logger.info(f"Full dataset size: {len(full_df)} samples")
        logger.info(f"Attack distribution:\n{full_df['attack_type'].value_counts()}")

        if save:
            # Save raw version
            raw_path = os.path.join(settings.DATA_DIR, "raw", "full_dataset.csv")
            full_df.to_csv(raw_path, index=False)
            logger.info(f"[OK] Dataset saved to: {raw_path}")

            # Save summary stats
            stats_path = os.path.join(settings.DATA_DIR, "raw", "dataset_stats.json")
            stats = {
                "total_samples": len(full_df),
                "normal_samples": len(normal_df),
                "attack_samples": len(full_df) - len(normal_df),
                "attack_types": full_df["attack_type"].value_counts().to_dict(),
                "feature_columns": settings.FEATURE_COLUMNS,
                "generated_at": datetime.now().isoformat()
            }
            with open(stats_path, "w") as f:
                json.dump(stats, f, indent=2)
            logger.info(f"[OK] Stats saved to: {stats_path}")

        return full_df


# ─────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    simulator = DataSimulator()
    df = simulator.generate_full_dataset(save=True)

    print("\n" + "="*50)
    print("DATASET SUMMARY")
    print("="*50)
    print(f"Total samples    : {len(df)}")
    print(f"Features         : {len(settings.FEATURE_COLUMNS)}")
    print(f"\nAttack breakdown :")
    print(df["attack_type"].value_counts())
    print(f"\nFirst 3 rows:")
    print(df[settings.FEATURE_COLUMNS].head(3))
    print("="*50)