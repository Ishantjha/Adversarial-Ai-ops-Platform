# src/mitigation/mitigation_engine.py
# Auto-mitigation engine that responds to detected attacks
# Takes automated defensive actions based on alert severity

import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict
from src.utils.logger import setup_logger
from config.settings import settings

logger = setup_logger("mitigation_engine")

# ─────────────────────────────────────────
# MITIGATION ACTIONS
# ─────────────────────────────────────────

class MitigationAction:
    """All possible automated response actions."""
    RATE_LIMIT        = "rate_limit"        # Slow down requests
    BLOCK_IP          = "block_ip"          # Block suspicious source
    ISOLATE_SERVICE   = "isolate_service"   # Isolate affected service
    SCALE_UP          = "scale_up"          # Add more resources
    FLUSH_CACHE       = "flush_cache"       # Clear poisoned cache
    RESET_MODEL       = "reset_model"       # Roll back ML model
    TRIGGER_RETRAIN   = "trigger_retrain"   # Retrain on clean data
    ALERT_TEAM        = "alert_team"        # Notify security team
    THROTTLE_NETWORK  = "throttle_network"  # Limit network traffic
    ENABLE_WAF        = "enable_waf"        # Enable web app firewall


# ─────────────────────────────────────────
# MITIGATION PLAYBOOKS
# ─────────────────────────────────────────

# Each attack type has a specific playbook of actions
ATTACK_PLAYBOOKS = {
    "dos_attack": [
        MitigationAction.RATE_LIMIT,
        MitigationAction.THROTTLE_NETWORK,
        MitigationAction.SCALE_UP,
        MitigationAction.ENABLE_WAF,
        MitigationAction.ALERT_TEAM
    ],
    "data_poisoning": [
        MitigationAction.FLUSH_CACHE,
        MitigationAction.RESET_MODEL,
        MitigationAction.TRIGGER_RETRAIN,
        MitigationAction.ALERT_TEAM
    ],
    "log_injection": [
        MitigationAction.BLOCK_IP,
        MitigationAction.ENABLE_WAF,
        MitigationAction.FLUSH_CACHE,
        MitigationAction.ALERT_TEAM
    ],
    "model_evasion": [
        MitigationAction.TRIGGER_RETRAIN,
        MitigationAction.RESET_MODEL,
        MitigationAction.ALERT_TEAM
    ],
    "fgsm_attack": [
        MitigationAction.RATE_LIMIT,
        MitigationAction.TRIGGER_RETRAIN,
        MitigationAction.ALERT_TEAM
    ]
}

# Severity multiplier — higher severity = more aggressive response
SEVERITY_MULTIPLIER = {
    "LOW":      1,   # run first action only
    "MEDIUM":   2,   # run first 2 actions
    "HIGH":     3,   # run first 3 actions
    "CRITICAL": 99   # run ALL actions
}


# ─────────────────────────────────────────
# MITIGATION RESPONSE CLASS
# ─────────────────────────────────────────

class MitigationResponse:
    """Represents a single mitigation response to an alert."""

    def __init__(self, alert_id, attack_type, severity, actions_taken):
        self.id            = datetime.now().strftime("%Y%m%d%H%M%S%f")
        self.timestamp     = datetime.now().isoformat()
        self.alert_id      = alert_id
        self.attack_type   = attack_type
        self.severity      = severity
        self.actions_taken = actions_taken
        self.success       = True
        self.duration_ms   = 0

    def to_dict(self):
        return {
            "id":            self.id,
            "timestamp":     self.timestamp,
            "alert_id":      self.alert_id,
            "attack_type":   self.attack_type,
            "severity":      self.severity,
            "actions_taken": self.actions_taken,
            "success":       self.success,
            "duration_ms":   self.duration_ms
        }


# ─────────────────────────────────────────
# MAIN MITIGATION ENGINE
# ─────────────────────────────────────────

class MitigationEngine:
    """
    Auto-mitigation engine.
    - Receives alerts from AlertEngine
    - Selects correct playbook per attack type
    - Executes mitigation actions
    - Tracks all responses
    - Handles cooldown to avoid action spam
    """

    def __init__(self):
        # Response history
        self.response_history = []
        self.action_counts    = defaultdict(int)

        # Cooldown tracking — prevent same action firing too often
        self.cooldown_tracker = {}
        self.cooldown_seconds = 30  # 30 sec cooldown per action

        # Blocked IPs (simulated)
        self.blocked_ips = set()

        # Rate limited services (simulated)
        self.rate_limited = {}

        # Retrain queue
        self.retrain_queue = []
        self.retrain_threshold = settings.RETRAIN_TRIGGER_COUNT

        # Mitigation log file
        self.log_path = os.path.join(
            settings.LOGS_DIR, "mitigations.json"
        )
        os.makedirs(settings.LOGS_DIR, exist_ok=True)

        logger.info("MitigationEngine initialized")

    # ─────────────────────────────────────────
    # CORE RESPONSE
    # ─────────────────────────────────────────

    def respond(self, alert):
        """
        Main entry point.
        Receives an Alert object and executes appropriate actions.
        Returns MitigationResponse.
        """
        start_time = time.time()

        logger.info(
            f"Responding to {alert.attack_type} | "
            f"severity={alert.severity}"
        )

        # Get playbook for this attack type
        playbook = ATTACK_PLAYBOOKS.get(
            alert.attack_type,
            [MitigationAction.ALERT_TEAM]  # default
        )

        # How many actions to take based on severity
        max_actions = SEVERITY_MULTIPLIER.get(alert.severity, 1)
        actions_to_run = playbook[:max_actions]

        # Execute each action
        actions_taken = []
        for action in actions_to_run:
            success = self._execute_action(
                action, alert.attack_type, alert.severity
            )
            if success:
                actions_taken.append(action)
                self.action_counts[action] += 1

        # Build response record
        response = MitigationResponse(
            alert_id     = alert.id,
            attack_type  = alert.attack_type,
            severity     = alert.severity,
            actions_taken= actions_taken
        )
        response.duration_ms = int((time.time() - start_time) * 1000)

        # Store response
        self.response_history.append(response)
        self._log_response(response)

        logger.info(
            f"Mitigation complete | actions={actions_taken} | "
            f"duration={response.duration_ms}ms"
        )

        return response

    # ─────────────────────────────────────────
    # ACTION EXECUTORS
    # ─────────────────────────────────────────

    def _execute_action(self, action, attack_type, severity):
        """
        Executes a single mitigation action.
        In production this would call real APIs.
        Here we simulate the actions with logging.
        """
        # Check cooldown
        if self._is_on_cooldown(action):
            logger.info(f"Action {action} is on cooldown, skipping")
            return False

        # Execute the action
        if action == MitigationAction.RATE_LIMIT:
            return self._do_rate_limit(severity)

        elif action == MitigationAction.BLOCK_IP:
            return self._do_block_ip()

        elif action == MitigationAction.ISOLATE_SERVICE:
            return self._do_isolate_service(attack_type)

        elif action == MitigationAction.SCALE_UP:
            return self._do_scale_up(severity)

        elif action == MitigationAction.FLUSH_CACHE:
            return self._do_flush_cache()

        elif action == MitigationAction.RESET_MODEL:
            return self._do_reset_model()

        elif action == MitigationAction.TRIGGER_RETRAIN:
            return self._do_trigger_retrain()

        elif action == MitigationAction.ALERT_TEAM:
            return self._do_alert_team(attack_type, severity)

        elif action == MitigationAction.THROTTLE_NETWORK:
            return self._do_throttle_network(severity)

        elif action == MitigationAction.ENABLE_WAF:
            return self._do_enable_waf()

        return False

    def _do_rate_limit(self, severity):
        limit = {"LOW": 500, "MEDIUM": 200, "HIGH": 100, "CRITICAL": 10}
        rate  = limit.get(severity, 100)
        self.rate_limited["api"] = rate
        logger.warning(f"[ACTION] Rate limit applied: {rate} req/s")
        self._set_cooldown(MitigationAction.RATE_LIMIT)
        return True

    def _do_block_ip(self):
        # Simulate blocking a suspicious IP
        fake_ip = f"192.168.{len(self.blocked_ips)%255}.{len(self.blocked_ips)%100}"
        self.blocked_ips.add(fake_ip)
        logger.warning(f"[ACTION] IP blocked: {fake_ip}")
        self._set_cooldown(MitigationAction.BLOCK_IP)
        return True

    def _do_isolate_service(self, attack_type):
        logger.warning(f"[ACTION] Service isolated due to: {attack_type}")
        self._set_cooldown(MitigationAction.ISOLATE_SERVICE)
        return True

    def _do_scale_up(self, severity):
        nodes = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 5}
        n     = nodes.get(severity, 1)
        logger.warning(f"[ACTION] Scaling up: +{n} nodes added")
        self._set_cooldown(MitigationAction.SCALE_UP)
        return True

    def _do_flush_cache(self):
        logger.warning("[ACTION] Cache flushed — poisoned data cleared")
        self._set_cooldown(MitigationAction.FLUSH_CACHE)
        return True

    def _do_reset_model(self):
        logger.warning("[ACTION] ML model rolled back to last clean checkpoint")
        self._set_cooldown(MitigationAction.RESET_MODEL)
        return True

    def _do_trigger_retrain(self):
        self.retrain_queue.append(datetime.now().isoformat())
        logger.warning(
            f"[ACTION] Model retraining triggered | "
            f"queue size: {len(self.retrain_queue)}"
        )
        self._set_cooldown(MitigationAction.TRIGGER_RETRAIN)
        return True

    def _do_alert_team(self, attack_type, severity):
        msg = (
            f"[ACTION] SECURITY ALERT SENT TO TEAM\n"
            f"         Attack: {attack_type}\n"
            f"         Severity: {severity}\n"
            f"         Time: {datetime.now().isoformat()}"
        )
        logger.warning(msg)
        self._set_cooldown(MitigationAction.ALERT_TEAM)
        return True

    def _do_throttle_network(self, severity):
        limit = {"LOW": "50%", "MEDIUM": "30%", "HIGH": "10%", "CRITICAL": "1%"}
        rate  = limit.get(severity, "10%")
        logger.warning(f"[ACTION] Network throttled to: {rate} capacity")
        self._set_cooldown(MitigationAction.THROTTLE_NETWORK)
        return True

    def _do_enable_waf(self):
        logger.warning("[ACTION] Web Application Firewall enabled")
        self._set_cooldown(MitigationAction.ENABLE_WAF)
        return True

    # ─────────────────────────────────────────
    # COOLDOWN MANAGEMENT
    # ─────────────────────────────────────────

    def _set_cooldown(self, action):
        """Sets cooldown timestamp for an action."""
        self.cooldown_tracker[action] = datetime.now()

    def _is_on_cooldown(self, action):
        """Returns True if action is still in cooldown period."""
        if action not in self.cooldown_tracker:
            return False
        elapsed = (datetime.now() - self.cooldown_tracker[action]).seconds
        return elapsed < self.cooldown_seconds

    # ─────────────────────────────────────────
    # STATISTICS
    # ─────────────────────────────────────────

    def get_stats(self):
        """Returns mitigation statistics."""
        return {
            "total_responses":  len(self.response_history),
            "action_counts":    dict(self.action_counts),
            "blocked_ips":      len(self.blocked_ips),
            "rate_limited":     self.rate_limited,
            "retrain_queue":    len(self.retrain_queue),
            "recent_responses": [
                r.to_dict() for r in self.response_history[-5:]
            ]
        }

    # ─────────────────────────────────────────
    # LOGGING
    # ─────────────────────────────────────────

    def _log_response(self, response):
        """Saves mitigation response to JSON log."""
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, "r") as f:
                    data = json.load(f)
            else:
                data = []
            data.append(response.to_dict())
            with open(self.log_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to log response: {e}")


# ─────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "C:\\Users\\ISHANT JHA\\aiops-platform")

    from src.detectors.alert_engine import AlertEngine

    logger.info("Testing Mitigation Engine...")

    # Initialize both engines
    alert_engine      = AlertEngine()
    mitigation_engine = MitigationEngine()

    # Test samples — one per attack type
    test_samples = {
        "dos_attack": {
            "cpu_usage": 97.0,    "memory_usage": 95.0,
            "network_in": 12000.0,"network_out": 9000.0,
            "disk_read": 100.0,   "disk_write": 80.0,
            "request_rate": 80000.0, "error_rate": 75.0,
            "response_time": 25000.0,"active_connections": 12000.0
        },
        "data_poisoning": {
            "cpu_usage": 98.0,    "memory_usage": 94.0,
            "network_in": 510.0,  "network_out": 310.0,
            "disk_read": 102.0,   "disk_write": 82.0,
            "request_rate": 1020.0,"error_rate": 80.0,
            "response_time": 8000.0,"active_connections": 510.0
        },
        "log_injection": {
            "cpu_usage": 45.0,    "memory_usage": 58.0,
            "network_in": 8000.0, "network_out": 7000.0,
            "disk_read": 105.0,   "disk_write": 85.0,
            "request_rate": 30000.0,"error_rate": 2.0,
            "response_time": 210.0, "active_connections": 9000.0
        },
        "model_evasion": {
            "cpu_usage": 72.0,    "memory_usage": 78.0,
            "network_in": 520.0,  "network_out": 310.0,
            "disk_read": 350.0,   "disk_write": 300.0,
            "request_rate": 1100.0,"error_rate": 10.0,
            "response_time": 220.0,"active_connections": 530.0
        }
    }

    print("\n" + "="*55)
    print("MITIGATION ENGINE TEST")
    print("="*55)

    for name, metrics in test_samples.items():
        print(f"\n--- Testing: {name.upper()} ---")

        # Step 1: Detect
        alert = alert_engine.analyze(metrics)
        if alert:
            print(f"Alert: [{alert.severity}] {alert.attack_type} | score={alert.anomaly_score}")

            # Step 2: Mitigate
            response = mitigation_engine.respond(alert)
            print(f"Actions taken: {response.actions_taken}")
            print(f"Response time: {response.duration_ms}ms")
        else:
            print("No alert fired (detected as normal)")

    # Print final stats
    print("\n" + "="*55)
    print("FINAL MITIGATION STATS")
    print("="*55)
    stats = mitigation_engine.get_stats()
    print(f"Total responses : {stats['total_responses']}")
    print(f"Blocked IPs     : {stats['blocked_ips']}")
    print(f"Retrain queue   : {stats['retrain_queue']}")
    print(f"Action counts   :")
    for action, count in stats["action_counts"].items():
        print(f"  {action}: {count}")

    print("\n[OK] Step 5 Complete!")
    print("Mitigation log saved to: logs/mitigations.json")