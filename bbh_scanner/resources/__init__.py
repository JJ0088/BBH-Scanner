"""Governance risorse: sensori (temp/carico/batteria) + governor adattivo."""

from bbh_scanner.resources.governor import Governor, Mode, ResourcePlan, decide
from bbh_scanner.resources.sensors import SensorReading, sample_sensors

__all__ = ["Governor", "Mode", "ResourcePlan", "decide", "SensorReading", "sample_sensors"]
