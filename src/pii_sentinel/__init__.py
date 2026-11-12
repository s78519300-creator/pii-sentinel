"""pii-sentinel: find and mask personal data, including Indian identifiers."""

__version__ = "0.1.0"

from .detectors import DETECTORS, Detector, select  # noqa: E402
from .scanner import Finding, mask_text, mask_value, scan_paths, scan_text  # noqa: E402

__all__ = ["DETECTORS", "Detector", "select", "Finding", "mask_text", "mask_value", "scan_paths", "scan_text"]
