"""
Network security checks module.

This module contains security checks related to network security,
including firewall configuration, open ports, and SSL/TLS security.
"""

from .firewall import FirewallCheck
from .open_ports import OpenPortsCheck
from .ssl_tls import SSLTLSCheck

__all__ = [
    'FirewallCheck',
    'OpenPortsCheck',
    'SSLTLSCheck'
]

# Registry of available network checks
NETWORK_CHECKS = {
    'firewall': FirewallCheck,
    'open_ports': OpenPortsCheck,
    'ssl_tls': SSLTLSCheck
}