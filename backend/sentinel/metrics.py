import logging
from collections import defaultdict
import time

logger = logging.getLogger(__name__)

class SentinelMetricsCollector:
    """
    Prometheus-compatible metrics collector for Sentinel Playbooks.
    """
    def __init__(self):
        # Counters
        self.playbooks_total = 0
        self.approved_total = 0

        # Histogram for generation seconds
        self.duration_buckets = [0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0]
        self.duration_counts = [0] * len(self.duration_buckets)
        self.duration_sum = 0.0
        self.duration_total = 0

    def inc_playbooks_total(self):
        """Increment total generated playbooks counter."""
        self.playbooks_total += 1

    def inc_approved_total(self):
        """Increment total approved playbooks counter."""
        self.approved_total += 1

    def observe_generation(self, duration_seconds: float):
        """Record playbook generation duration."""
        self.duration_sum += duration_seconds
        self.duration_total += 1
        for i, bucket in enumerate(self.duration_buckets):
            if duration_seconds <= bucket:
                self.duration_counts[i] += 1
                break

    def to_prometheus(self) -> str:
        """Generate Prometheus text format for Sentinel metrics."""
        lines = []

        # playbooks_total
        lines.append("# HELP sentinel_playbooks_total Total number of generated playbooks")
        lines.append("# TYPE sentinel_playbooks_total counter")
        lines.append(f"sentinel_playbooks_total {self.playbooks_total}")

        # approved_total
        lines.append("")
        lines.append("# HELP sentinel_approved_total Total number of approved playbooks")
        lines.append("# TYPE sentinel_approved_total counter")
        lines.append(f"sentinel_approved_total {self.approved_total}")

        # generation_seconds
        if self.duration_total > 0:
            lines.append("")
            lines.append("# HELP sentinel_generation_seconds Duration of playbook generation in seconds")
            lines.append("# TYPE sentinel_generation_seconds histogram")
            
            cumulative = 0
            for i, bucket in enumerate(self.duration_buckets):
                cumulative += self.duration_counts[i]
                lines.append(f'sentinel_generation_seconds_bucket{{le="{bucket}"}} {cumulative}')
            
            lines.append(f'sentinel_generation_seconds_bucket{{le="+Inf"}} {self.duration_total}')
            lines.append(f'sentinel_generation_seconds_sum {self.duration_sum:.2f}')
            lines.append(f'sentinel_generation_seconds_count {self.duration_total}')
        else:
            lines.append("")
            lines.append("# HELP sentinel_generation_seconds Duration of playbook generation in seconds")
            lines.append("# TYPE sentinel_generation_seconds histogram")
            for bucket in self.duration_buckets:
                lines.append(f'sentinel_generation_seconds_bucket{{le="{bucket}"}} 0')
            lines.append(f'sentinel_generation_seconds_bucket{{le="+Inf"}} 0')
            lines.append(f'sentinel_generation_seconds_sum 0.00')
            lines.append(f'sentinel_generation_seconds_count 0')


        return "\n".join(lines) + "\n"

# Global singleton
sentinel_metrics = SentinelMetricsCollector()
