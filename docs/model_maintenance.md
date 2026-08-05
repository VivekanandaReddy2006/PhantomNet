# Model Maintenance Guide

## 1. Retraining Schedule
The Isolation Forest model should be retrained periodically to adapt to evolving network traffic patterns and new attack vectors.

### Recommended Schedule: **Weekly**
- **Trigger:** Automated job every Sunday at 02:00 AM.
- **Data Window:** Last 30 days of traffic logs.

### Drift Detection Trigger
Retrain immediately if:
- **False Positive Rate** exceeds 5% for 24 hours.
- **F1 Score** on labeled test set drops below 0.45.
- **Data Distribution Shift:** Major changes in protocol usage (e.g., new UDP service deployed).

## 2. Monitoring
Monitor the following metrics via the `/api/v1/model/metrics` endpoint and dashboard:
- **Inference Latency:** Should remain < 50ms.
- **Anomaly Rate:** Expected range 5-15%. Sudden spikes > 30% indicate either a massive attack or model failure.

## 3. Versioning Strategy
- **Semantic Versioning:** `vX.Y` (e.g., v1.2)
    - `X`: Major architecture change (e.g., switching from Isolation Forest to Autoencoder).
    - `Y`: Retraining with new data or hyperparameter tuning.
- **Tracking:** All versions must be logged in `models/versions.json`.

## 4. Rollback Procedure
If a new model performs poorly:
1. Identify the previous stable version from `models/versions.json`.
2. Rename/Copy the previous model file to `models/isolation_forest_optimized_v2.pkl`.
3. Restart the backend service to reload the model.

## 5. Hardware Requirements (V3)
For optimal performance of the V3 model pipeline, including the AI-enhanced narrative generation and anomaly detection, the following hardware specifications are recommended:
- **CPU:** 8+ Cores (e.g., Intel Core i7/i9 12th Gen+ or AMD Ryzen 7/9 5000+ series)
- **RAM:** 32 GB minimum (64 GB recommended for large batch processing)
- **GPU:** NVIDIA RTX 3080 / 4080 or better (with at least 12GB VRAM) for Ollama inference and model offloading.
- **Storage:** 1 TB NVMe SSD (SATA SSDs will heavily bottleneck database/log reads)
- **Network:** 1 Gbps NIC minimum (for capturing un-sampled high-volume honey pot traffic)
