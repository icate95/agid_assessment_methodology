"""Modulo core per AGID Assessment Methodology.

Questo modulo contiene le classi principali del framework:
- Assessment: per gestire le valutazioni di sicurezza
- Scanner: per eseguire le scansioni sui sistemi target
"""

from .assessment import Assessment
from .scanner import Scanner

__all__ = ["Assessment", "Scanner"]