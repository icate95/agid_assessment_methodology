"""Modulo checks per AGID Assessment Methodology.

Questo modulo contiene tutti i controlli di sicurezza organizzati per categoria:
- authentication: controlli su autenticazione e gestione utenti
- system: controlli di sistema di base
- network: controlli di rete e firewall (future)
- malware: controlli antimalware (future)
- backup: controlli sui backup (future)
"""

from .base import BaseCheck, CheckResult, CheckStatus
from .registry import CheckRegistry

# Import dei controlli specifici
from .system.system_info import SystemInfoCheck
from .system.basic_security import BasicSecurityCheck
from .authentication.password_policy import PasswordPolicyCheck

# Registro globale dei controlli
registry = CheckRegistry()

# Registra automaticamente i controlli disponibili
registry.register(SystemInfoCheck())
registry.register(BasicSecurityCheck())
registry.register(PasswordPolicyCheck())

__all__ = [
    "BaseCheck",
    "CheckResult",
    "CheckStatus",
    "CheckRegistry",
    "registry",
    "SystemInfoCheck",
    "BasicSecurityCheck",
    "PasswordPolicyCheck",
]