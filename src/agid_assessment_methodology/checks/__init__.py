"""Modulo checks per AGID Assessment Methodology.

Questo modulo contiene tutti i controlli di sicurezza organizzati per categoria:
- authentication: controlli su autenticazione e gestione utenti
- system: controlli di sistema di base
- network: controlli di rete e firewall
- malware: controlli antimalware e protezione
- backup: controlli sui backup (future)
"""

import logging
import importlib
import pkgutil
import sys
from pathlib import Path

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

from .base import BaseCheck, CheckResult, CheckStatus
from .registry import CheckRegistry

# Registro globale dei controlli
registry = CheckRegistry()

def import_submodules(package_name):
    """
    Importa tutti i sottmoduli di un pacchetto.

    Args:
        package_name: Nome del pacchetto da importare
    """
    package = sys.modules.get(package_name)
    if not package:
        package = importlib.import_module(package_name)

    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        full_name = f"{package_name}.{name}"
        try:
            results[full_name] = importlib.import_module(full_name)
        except ImportError as e:
            logger.error(f"Errore durante l'importazione di {full_name}: {e}")

    return results

def auto_register_checks(package_path):
    """
    Registra automaticamente i controlli trovati in un pacchetto.

    Args:
        package_path: Percorso del pacchetto da analizzare
    """
    import importlib
    import importlib.util
    import sys
    from pathlib import Path

    package_dir = Path(package_path)

    # Assicurati che la directory sia nel path di Python
    if str(package_dir.parent) not in sys.path:
        sys.path.insert(0, str(package_dir.parent))

    def import_module_from_path(module_path):
        """Importa un modulo dal percorso del file."""
        try:
            # Converti il percorso in un nome di modulo
            relative_path = module_path.relative_to(package_dir.parent)
            module_name = str(relative_path).replace('/', '.')[:-3]

            # Importa il modulo
            module = importlib.import_module(module_name)
            return module
        except Exception as e:
            logger.error(f"Errore durante l'importazione di {module_path}: {e}")
            return None

    # Trova tutti i file .py che non sono __init__.py
    for module_path in package_dir.rglob('*.py'):
        if module_path.stem.startswith('__'):
            continue

        module = import_module_from_path(module_path)

        if module:
            # Cerca classi che ereditano da BaseCheck
            for name, obj in module.__dict__.items():
                try:
                    if (isinstance(obj, type) and
                        issubclass(obj, BaseCheck) and
                        obj is not BaseCheck and
                        not name.startswith('_')):

                        check_instance = obj()
                        registry.register(check_instance)
                        # logger.info(f"Registrato check: {name}")
                except Exception as e:
                    logger.error(f"Errore durante la registrazione di {name}: {e}")

# Importa e registra controlli
try:
    checks_package = 'agid_assessment_methodology.checks'
    checks_path = Path(__file__).parent

    # logger.info(f"Cercando controlli in: {checks_path}")
    auto_register_checks(checks_path)
except Exception as e:
    logger.error(f"Errore durante la registrazione automatica: {e}")

# Esporta gli stessi elementi di prima
from .system.system_info import SystemInfoCheck
from .system.basic_security import BasicSecurityCheck
from .authentication.password_policy import PasswordPolicyCheck
from .network.firewall import FirewallCheck
from .network.open_ports import OpenPortsCheck
from .network.ssl_tls import SSLTLSCheck
from .malware.antivirus import AntivirusCheck
from .malware.definitions import DefinitionsCheck
from .malware.quarantine import QuarantineCheck

# Registrazione manuale per sicurezza
def _manual_register_checks():
    checks_to_register = [
        SystemInfoCheck(),
        BasicSecurityCheck(),
        PasswordPolicyCheck(),
        FirewallCheck(),
        OpenPortsCheck(),
        SSLTLSCheck(),
        AntivirusCheck(),
        DefinitionsCheck(),
        QuarantineCheck()
    ]

    for check in checks_to_register:
        registry.register(check)

_manual_register_checks()

__all__ = [
    "BaseCheck",
    "CheckResult",
    "CheckStatus",
    "CheckRegistry",
    "registry",
    # System checks
    "SystemInfoCheck",
    "BasicSecurityCheck",
    # Authentication checks
    "PasswordPolicyCheck",
    # Network checks
    "FirewallCheck",
    "OpenPortsCheck",
    "SSLTLSCheck",
    # Malware checks
    "AntivirusCheck",
    "DefinitionsCheck",
    "QuarantineCheck",
]

# Debug logging
# logger.info(f"Checks importati. Totale check registrati: {len(registry._checks)}")
# for check_id, check in registry._checks.items():
#     logger.info(f"- {check_id}: {check.name} (Categoria: {check.category})")