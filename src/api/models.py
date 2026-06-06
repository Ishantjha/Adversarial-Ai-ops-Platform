# src/api/models.py
# Pydantic models for request/response validation

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

# ─────────────────────────────────────────
# REQUEST MODELS
# ─────────────────────────────────────────

class MetricsInput(BaseModel):
    """Input metrics for real-time analysis."""
    cpu_usage:          float = Field(..., ge=0, le=100,   description="CPU usage %")
    memory_usage:       float = Field(..., ge=0, le=100,   description="Memory usage %")
    network_in:         float = Field(..., ge=0,           description="Network in MB/s")
    network_out:        float = Field(..., ge=0,           description="Network out MB/s")
    disk_read:          float = Field(..., ge=0,           description="Disk read MB/s")
    disk_write:         float = Field(..., ge=0,           description="Disk write MB/s")
    request_rate:       float = Field(..., ge=0,           description="Requests per second")
    error_rate:         float = Field(..., ge=0, le=100,   description="Error rate %")
    response_time:      float = Field(..., ge=0,           description="Response time ms")
    active_connections: float = Field(..., ge=0,           description="Active connections")

    class Config:
        json_schema_extra = {
            "example": {
                "cpu_usage": 42.0,
                "memory_usage": 55.0,
                "network_in": 480.0,
                "network_out": 290.0,
                "disk_read": 98.0,
                "disk_write": 78.0,
                "request_rate": 980.0,
                "error_rate": 0.4,
                "response_time": 195.0,
                "active_connections": 490.0
            }
        }

# ─────────────────────────────────────────
# RESPONSE MODELS
# ─────────────────────────────────────────

class DetectionResult(BaseModel):
    """Result of analyzing a single metrics sample."""
    is_attack:              bool
    anomaly_score:          float
    isolation_forest_flag:  bool
    autoencoder_flag:       bool
    reconstruction_error:   float
    severity:               Optional[str] = None
    attack_type:            Optional[str] = None
    mitigation_actions:     Optional[List[str]] = None
    timestamp:              str = Field(
                                default_factory=lambda:
                                datetime.now().isoformat()
                            )

class AlertSummary(BaseModel):
    """Summary of a single alert."""
    id:               str
    timestamp:        str
    severity:         str
    attack_type:      str
    anomaly_score:    float
    resolved:         bool

class StatsResponse(BaseModel):
    """Platform-wide statistics."""
    total_analyzed:   int
    total_attacks:    int
    total_normal:     int
    detection_rate:   float
    alert_counts:     Dict[str, int]
    attack_counts:    Dict[str, int]
    recent_alerts:    int

class HealthResponse(BaseModel):
    """API health check response."""
    status:           str
    version:          str
    models_loaded:    bool
    timestamp:        str

class MitigationStats(BaseModel):
    """Mitigation engine statistics."""
    total_responses:  int
    blocked_ips:      int
    retrain_queue:    int
    action_counts:    Dict[str, int]