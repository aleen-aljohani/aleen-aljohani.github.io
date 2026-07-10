"""SmartHoneyNet — Hunt, Detect and Analyze Attacks on Smart-Home Networks.

A reproducible, container-friendly rebuild of the University of Jeddah
graduation project that combined Honeypots, an Intrusion Detection System
and the ELK stack to hunt, detect and analyse attacks against smart-home
(IoT) networks.

The package is intentionally dependency-light and runnable end-to-end on a
single host so the whole detection pipeline can be exercised and tested
without provisioning virtual machines.
"""

from .models import Event, Alert, EventType
from .config import Settings, DetectionConfig

__all__ = ["Event", "Alert", "EventType", "Settings", "DetectionConfig"]
__version__ = "2.0.0"
