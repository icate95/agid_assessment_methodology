# File: src/agid_assessment_methodology/cli/__init__.py
# Aggiungere alias per comando breve

from .main import app

# Crea alias per comando breve
agid_app = app

# Registra entry points per entrambi i nomi
__all__ = ["app", "agid_app"]