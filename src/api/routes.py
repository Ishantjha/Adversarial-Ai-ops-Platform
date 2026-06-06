# src/api/routes.py
# All API route handlers

from fastapi import APIRouter, HTTPException, BackgroundTasks
from src.api.models import (
    MetricsInput, DetectionResult, AlertSummary,
    StatsResponse, HealthResponse, MitigationStats
)
from src.utils.logger import setup_logger
from config.settings import settings
from datetime import datetime
from typing import List, Dict, Any

logger = setup_logger("routes")

router = APIRouter()

# These will be injected from main app
alert_engine      = None
mitigation_engine = None

def init_engines(ae, me):
    """Initialize engines — called from app.py on startup."""
    global alert_engine, mitigation_engine
    alert_engine      = ae
    mitigation_engine = me
    logger.info("Engines injected into routes")


# ─────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────

@router.get("/health", response_model=HealthResponse, tags=["System"])
def health_check():
    """Check if API and models are running."""
    return HealthResponse(
        status       = "healthy",
        version      = settings.APP_VERSION,
        models_loaded= alert_engine is not None and
                       alert_engine.detector.is_trained,
        timestamp    = datetime.now().isoformat()
    )


# ─────────────────────────────────────────
# DETECTION ENDPOINTS
# ─────────────────────────────────────────

@router.post("/analyze", response_model=DetectionResult, tags=["Detection"])
def analyze_metrics(
    metrics: MetricsInput,
    background_tasks: BackgroundTasks
):
    """
    Analyze a single metrics sample in real-time.
    Returns detection result + mitigation actions if attack found.
    """
    if alert_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Alert engine not initialized"
        )

    try:
        metrics_dict = metrics.model_dump()

        # Run detection
        alert = alert_engine.analyze(metrics_dict)

        if alert:
            # Run mitigation in background
            background_tasks.add_task(
                mitigation_engine.respond, alert
            )

            return DetectionResult(
                is_attack             = True,
                anomaly_score         = alert.anomaly_score,
                isolation_forest_flag = alert.isolation_forest,
                autoencoder_flag      = alert.autoencoder,
                reconstruction_error  = alert.reconstruction_error,
                severity              = alert.severity,
                attack_type           = alert.attack_type,
                mitigation_actions    = ATTACK_PLAYBOOKS_PREVIEW.get(
                                            alert.attack_type, []
                                        )
            )
        else:
            # Normal traffic
            result = alert_engine.detector.predict_single(metrics_dict)
            return DetectionResult(
                is_attack             = False,
                anomaly_score         = result["anomaly_score"],
                isolation_forest_flag = result["isolation_forest_flag"],
                autoencoder_flag      = result["autoencoder_flag"],
                reconstruction_error  = result["reconstruction_error"],
                severity              = None,
                attack_type           = "none",
                mitigation_actions    = []
            )

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────
# ALERTS ENDPOINTS
# ─────────────────────────────────────────

@router.get("/alerts", tags=["Alerts"])
def get_alerts(limit: int = 20):
    """Get recent alerts."""
    if alert_engine is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    return {
        "alerts": alert_engine.get_recent_alerts(limit),
        "total":  len(alert_engine.alert_history)
    }

@router.get("/alerts/stats", response_model=StatsResponse, tags=["Alerts"])
def get_alert_stats():
    """Get full detection statistics."""
    if alert_engine is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    return StatsResponse(**alert_engine.get_stats())

@router.delete("/alerts/clear", tags=["Alerts"])
def clear_alerts():
    """Clear all alerts from memory."""
    if alert_engine is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    alert_engine.clear_alerts()
    return {"message": "All alerts cleared", "status": "ok"}


# ─────────────────────────────────────────
# MITIGATION ENDPOINTS
# ─────────────────────────────────────────

@router.get("/mitigation/stats", tags=["Mitigation"])
def get_mitigation_stats():
    """Get mitigation engine statistics."""
    if mitigation_engine is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    stats = mitigation_engine.get_stats()
    return {
        "total_responses": stats["total_responses"],
        "blocked_ips":     stats["blocked_ips"],
        "retrain_queue":   stats["retrain_queue"],
        "action_counts":   stats["action_counts"]
    }

@router.get("/mitigation/blocked-ips", tags=["Mitigation"])
def get_blocked_ips():
    """Get list of currently blocked IPs."""
    if mitigation_engine is None:
        raise HTTPException(status_code=503, detail="Engine not ready")
    return {
        "blocked_ips": list(mitigation_engine.blocked_ips),
        "count":       len(mitigation_engine.blocked_ips)
    }


# ─────────────────────────────────────────
# SIMULATION ENDPOINTS
# ─────────────────────────────────────────

@router.post("/simulate/attack/{attack_type}", tags=["Simulation"])
def simulate_attack(attack_type: str):
    """
    Simulate a specific attack type for testing.
    Useful for demo and dashboard testing.
    """
    attack_samples = {
        "dos": {
            "cpu_usage": 97.0,    "memory_usage": 95.0,
            "network_in": 12000.0,"network_out": 9000.0,
            "disk_read": 100.0,   "disk_write": 80.0,
            "request_rate": 80000.0,"error_rate": 75.0,
            "response_time": 25000.0,"active_connections": 12000.0
        },
        "poisoning": {
            "cpu_usage": 98.0,    "memory_usage": 94.0,
            "network_in": 510.0,  "network_out": 310.0,
            "disk_read": 102.0,   "disk_write": 82.0,
            "request_rate": 1020.0,"error_rate": 80.0,
            "response_time": 8000.0,"active_connections": 510.0
        },
        "injection": {
            "cpu_usage": 45.0,    "memory_usage": 58.0,
            "network_in": 8000.0, "network_out": 7000.0,
            "disk_read": 105.0,   "disk_write": 85.0,
            "request_rate": 30000.0,"error_rate": 2.0,
            "response_time": 210.0,"active_connections": 9000.0
        },
        "normal": {
            "cpu_usage": 42.0,    "memory_usage": 55.0,
            "network_in": 480.0,  "network_out": 290.0,
            "disk_read": 98.0,    "disk_write": 78.0,
            "request_rate": 980.0,"error_rate": 0.4,
            "response_time": 195.0,"active_connections": 490.0
        }
    }

    if attack_type not in attack_samples:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown attack type. Choose from: {list(attack_samples.keys())}"
        )

    metrics      = attack_samples[attack_type]
    metrics_obj  = MetricsInput(**metrics)

    from fastapi import BackgroundTasks
    bt = BackgroundTasks()
    return analyze_metrics(metrics_obj, bt)


# Preview of actions per attack (for response display)
ATTACK_PLAYBOOKS_PREVIEW = {
    "dos_attack":      ["rate_limit", "throttle_network", "scale_up", "enable_waf"],
    "data_poisoning":  ["flush_cache", "reset_model", "trigger_retrain"],
    "log_injection":   ["block_ip", "enable_waf", "flush_cache"],
    "model_evasion":   ["trigger_retrain", "reset_model"],
    "fgsm_attack":     ["rate_limit", "trigger_retrain"]
}