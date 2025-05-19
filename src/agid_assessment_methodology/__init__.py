"""AGID Assessment Methodology.

Framework per audit di sicurezza basato sui requisiti minimi ABSC.
Questo sistema fornisce controlli automatizzati di sicurezza, verifica della compliance,
reporting e capacità di scheduling per la valutazione della sicurezza dell'infrastruttura IT.

Features:
- Controlli di sicurezza modulari
- Supporto per Windows e Linux
- Report in multipli formati (JSON, CSV, HTML, PDF)
- Interfaccia CLI completa
- Sistema di scheduling
"""

__author__ = "Caterina Ianeselli"
__email__ = "ianesellicaterina@gmail.com"
__version__ = "0.1.0"

# Esporta le funzioni principali per un uso facile del package
from .core.assessment import Assessment
from .core.scanner import Scanner
#
# Lista di ciò che viene esportato quando si fa "from agid_assessment_methodology import *"
__all__ = [
    "Assessment",
    "Scanner",
    "__version__",
]