"""Modulo checks per AGID Assessment Methodology.

Questo modulo contiene tutti i controlli di sicurezza organizzati per categoria:
- authentication: controlli su autenticazione e gestione utenti
- system: controlli di sistema di base
- network: controlli di rete e firewall
- malware: controlli antimalware e protezione
- backup: controlli sui backup (future)
"""

from .base import BaseCheck, CheckResult, CheckStatus
from .registry import CheckRegistry

# Import dei controlli specifici
from .system.system_info import SystemInfoCheck
from .system.basic_security import BasicSecurityCheck
from .authentication.password_policy import PasswordPolicyCheck

# Import dei nuovi controlli network
from .network.firewall import FirewallCheck
from .network.open_ports import OpenPortsCheck
from .network.ssl_tls import SSLTLSCheck

# Import dei nuovi controlli malware
from .malware.antivirus import AntivirusCheck
from .malware.definitions import DefinitionsCheck
from .malware.quarantine import QuarantineCheck

# Registro globale dei controlli
registry = CheckRegistry()

# Registra automaticamente i controlli disponibili
# Sistema
registry.register(SystemInfoCheck())
registry.register(BasicSecurityCheck())

# Autenticazione
registry.register(PasswordPolicyCheck())

# Network
registry.register(FirewallCheck())
registry.register(OpenPortsCheck())
registry.register(SSLTLSCheck())

# Malware
registry.register(AntivirusCheck())
registry.register(DefinitionsCheck())
registry.register(QuarantineCheck())

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