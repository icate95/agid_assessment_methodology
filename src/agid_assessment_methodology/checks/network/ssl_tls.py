"""
SSL/TLS security check.

This module implements checks to verify SSL/TLS certificate validity,
security configuration, and compliance with security best practices.
"""

import logging
import socket
import ssl
import subprocess
import json
import platform
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse

from agid_assessment_methodology.checks.base import BaseCheck, CheckResult, CheckStatus

logger = logging.getLogger(__name__)


class SSLTLSCheck(BaseCheck):
    """Check for SSL/TLS certificate and configuration security."""

    def __init__(self):
        super().__init__()
        self.id = "ssl_tls"
        self.name = "SSL/TLS Security"
        self.description = "Verify SSL/TLS certificates and security configurations"
        self.category = "network"
        self.severity = "high"
        self.supported_os = ["windows", "linux", "macos"]

        # Common services to check
        self.common_services = [
            {"name": "HTTPS", "port": 443, "protocol": "https"},
            {"name": "SMTP TLS", "port": 587, "protocol": "smtp"},
            {"name": "IMAP TLS", "port": 993, "protocol": "imap"},
            {"name": "POP3 TLS", "port": 995, "protocol": "pop3"},
            {"name": "LDAPS", "port": 636, "protocol": "ldaps"}
        ]

    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Execute the SSL/TLS security check.

        Args:
            context: Execution context containing target and other details

        Returns:
            CheckResult with SSL/TLS security status
        """
        try:
            results = {
                'certificates': [],
                'services': [],
                'system_certificates': {},
                'vulnerabilities': [],
                'compliance': {}
            }

            # Get target from context
            target = context.get('target', 'localhost')

            # Check system certificate store
            system_certs = self._check_system_certificates(context)
            results['system_certificates'] = system_certs

            # Check SSL/TLS services on the target
            if target and target != 'localhost':
                services_check = self._check_ssl_services(target)
                results['services'] = services_check

            # Check for common SSL/TLS vulnerabilities
            vulnerabilities = self._check_ssl_vulnerabilities(target)
            results['vulnerabilities'] = vulnerabilities

            # Assess compliance with security standards
            compliance = self._assess_ssl_compliance(results)
            results['compliance'] = compliance

            # Determine overall status
            status, message = self._determine_overall_status(results)

            return CheckResult(
                status=CheckStatus(status),
                message=message,
                details=results,
                recommendations=self._generate_recommendations(results)
            )

        except Exception as e:
            logger.error(f"Error in SSL/TLS check: {str(e)}")
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Error during SSL/TLS check: {str(e)}",
                details={"error": str(e)}
            )

    def _check_system_certificates(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Check system certificate store and configuration."""
        os_type = context.get('os_type', platform.system().lower())
        cert_info = {
            'store_accessible': False,
            'expired_certificates': [],
            'expiring_soon': [],
            'total_certificates': 0
        }

        try:
            if os_type == 'windows':
                cert_info.update(self._check_windows_certificates())
            elif os_type == 'linux':
                cert_info.update(self._check_linux_certificates())
            elif os_type == 'darwin':
                cert_info.update(self._check_macos_certificates())

        except Exception as e:
            logger.error(f"Error checking system certificates: {str(e)}")
            cert_info['error'] = str(e)

        return cert_info

    def _check_windows_certificates(self) -> Dict[str, Any]:
        """Check Windows certificate store."""
        try:
            # Use PowerShell to check certificate store
            ps_command = """
            Get-ChildItem -Path Cert:\\LocalMachine\\My | 
            Select-Object Subject, NotAfter, NotBefore, Thumbprint, HasPrivateKey |
            ConvertTo-Json
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                certificates = json.loads(result.stdout)
                if isinstance(certificates, dict):
                    certificates = [certificates]

                cert_info = {
                    'store_accessible': True,
                    'total_certificates': len(certificates),
                    'expired_certificates': [],
                    'expiring_soon': []
                }

                now = datetime.now()
                warning_threshold = now + timedelta(days=30)

                for cert in certificates:
                    try:
                        # Parse certificate dates
                        not_after = datetime.strptime(cert['NotAfter'], '%m/%d/%Y %I:%M:%S %p')

                        if not_after < now:
                            cert_info['expired_certificates'].append({
                                'subject': cert['Subject'],
                                'expires': cert['NotAfter'],
                                'thumbprint': cert['Thumbprint']
                            })
                        elif not_after < warning_threshold:
                            cert_info['expiring_soon'].append({
                                'subject': cert['Subject'],
                                'expires': cert['NotAfter'],
                                'days_remaining': (not_after - now).days
                            })
                    except Exception as e:
                        logger.debug(f"Error parsing certificate date: {e}")

                return cert_info

        except Exception as e:
            logger.error(f"Error checking Windows certificates: {e}")

        return {'store_accessible': False, 'error': 'Unable to access certificate store'}

    def _check_linux_certificates(self) -> Dict[str, Any]:
        """Check Linux certificate store."""
        cert_paths = [
            '/etc/ssl/certs',
            '/usr/share/ca-certificates',
            '/etc/pki/tls/certs'
        ]

        cert_info = {
            'store_accessible': False,
            'total_certificates': 0,
            'ca_bundle_found': False,
            'paths_checked': cert_paths
        }

        for path in cert_paths:
            try:
                import os
                if os.path.exists(path):
                    cert_info['store_accessible'] = True

                    # Count certificate files
                    cert_files = [f for f in os.listdir(path)
                                 if f.endswith(('.crt', '.pem', '.cer'))]
                    cert_info['total_certificates'] += len(cert_files)

                    # Check for CA bundle
                    ca_files = [f for f in os.listdir(path)
                               if 'ca-bundle' in f.lower() or 'ca-certificates' in f.lower()]
                    if ca_files:
                        cert_info['ca_bundle_found'] = True

            except Exception as e:
                logger.debug(f"Error checking certificate path {path}: {e}")

        return cert_info

    def _check_macos_certificates(self) -> Dict[str, Any]:
        """Check macOS certificate store."""
        try:
            # Check keychain certificates
            result = subprocess.run(
                ["security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Count certificates in output
                cert_count = result.stdout.count('-----BEGIN CERTIFICATE-----')

                return {
                    'store_accessible': True,
                    'total_certificates': cert_count,
                    'system_keychain_accessible': True
                }

        except Exception as e:
            logger.error(f"Error checking macOS certificates: {e}")

        return {'store_accessible': False, 'error': 'Unable to access keychain'}

    def _check_ssl_services(self, target: str) -> List[Dict[str, Any]]:
        """Check SSL/TLS services on target."""
        services = []

        # Parse target to get hostname
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            services_to_check = [{"name": "Web Server", "port": port, "protocol": "https"}]
        else:
            hostname = target
            services_to_check = self.common_services

        for service in services_to_check:
            try:
                service_result = self._check_ssl_service(hostname, service['port'], service['name'])
                services.append(service_result)
            except Exception as e:
                logger.debug(f"Error checking {service['name']} on {hostname}:{service['port']}: {e}")

        return services

    def _check_ssl_service(self, hostname: str, port: int, service_name: str) -> Dict[str, Any]:
        """Check SSL/TLS configuration for a specific service."""
        service_info = {
            'service': service_name,
            'hostname': hostname,
            'port': port,
            'accessible': False,
            'certificate': {},
            'protocols': [],
            'ciphers': [],
            'security_issues': []
        }

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect to service
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    service_info['accessible'] = True

                    # Get certificate information
                    cert = ssock.getpeercert()
                    if cert:
                        service_info['certificate'] = self._parse_certificate_info(cert)

                    # Get protocol version
                    service_info['protocol_version'] = ssock.version()

                    # Get cipher information
                    cipher = ssock.cipher()
                    if cipher:
                        service_info['cipher'] = {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'bits': cipher[2]
                        }

                    # Check for security issues
                    service_info['security_issues'] = self._check_certificate_security_issues(cert, ssock)

        except socket.timeout:
            service_info['error'] = 'Connection timeout'
        except socket.gaierror:
            service_info['error'] = 'Name resolution failed'
        except ConnectionRefusedError:
            service_info['error'] = 'Connection refused'
        except ssl.SSLError as e:
            service_info['error'] = f'SSL error: {str(e)}'
        except Exception as e:
            service_info['error'] = f'Unexpected error: {str(e)}'

        return service_info

    def _parse_certificate_info(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        """Parse certificate information."""
        cert_info = {}

        try:
            # Basic certificate information
            cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
            cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
            cert_info['version'] = cert.get('version')
            cert_info['serial_number'] = cert.get('serialNumber')

            # Validity dates
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')

            if not_before:
                cert_info['not_before'] = not_before
            if not_after:
                cert_info['not_after'] = not_after

                # Calculate days until expiration
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    cert_info['days_until_expiry'] = days_until_expiry
                    cert_info['expires_soon'] = days_until_expiry < 30
                    cert_info['expired'] = days_until_expiry < 0
                except Exception as e:
                    logger.debug(f"Error parsing certificate expiry date: {e}")

            # Subject Alternative Names
            san = cert.get('subjectAltName', [])
            if san:
                cert_info['subject_alt_names'] = [name[1] for name in san]

            # Key usage and extended key usage
            extensions = cert.get('extensions', [])
            for ext in extensions:
                if 'keyUsage' in str(ext):
                    cert_info['key_usage'] = str(ext)
                elif 'extendedKeyUsage' in str(ext):
                    cert_info['extended_key_usage'] = str(ext)

        except Exception as e:
            logger.error(f"Error parsing certificate: {e}")
            cert_info['parse_error'] = str(e)

        return cert_info

    def _check_certificate_security_issues(self, cert: Dict[str, Any], ssock) -> List[Dict[str, Any]]:
        """Check for certificate security issues."""
        issues = []

        try:
            # Check certificate expiration
            not_after = cert.get('notAfter')
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days

                    if days_until_expiry < 0:
                        issues.append({
                            'severity': 'critical',
                            'issue': 'Certificate expired',
                            'details': f'Certificate expired {abs(days_until_expiry)} days ago'
                        })
                    elif days_until_expiry < 30:
                        issues.append({
                            'severity': 'high',
                            'issue': 'Certificate expires soon',
                            'details': f'Certificate expires in {days_until_expiry} days'
                        })
                except Exception as e:
                    logger.debug(f"Error checking certificate expiry: {e}")

            # Check protocol version
            protocol_version = ssock.version()
            if protocol_version:
                if protocol_version in ['SSLv2', 'SSLv3']:
                    issues.append({
                        'severity': 'critical',
                        'issue': 'Insecure protocol version',
                        'details': f'Using deprecated protocol: {protocol_version}'
                    })
                elif protocol_version in ['TLSv1', 'TLSv1.1']:
                    issues.append({
                        'severity': 'high',
                        'issue': 'Weak protocol version',
                        'details': f'Using weak protocol: {protocol_version}. Recommend TLS 1.2+'
                    })

            # Check cipher strength
            cipher = ssock.cipher()
            if cipher:
                cipher_name = cipher[0]
                key_length = cipher[2]

                if key_length < 128:
                    issues.append({
                        'severity': 'high',
                        'issue': 'Weak cipher key length',
                        'details': f'Cipher {cipher_name} uses {key_length} bits (recommend 128+)'
                    })

                # Check for known weak ciphers
                weak_ciphers = ['RC4', 'DES', '3DES', 'NULL']
                for weak_cipher in weak_ciphers:
                    if weak_cipher in cipher_name:
                        issues.append({
                            'severity': 'critical',
                            'issue': 'Weak cipher algorithm',
                            'details': f'Using weak cipher: {cipher_name}'
                        })

            # Check certificate chain (basic)
            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))

            if subject == issuer:
                issues.append({
                    'severity': 'medium',
                    'issue': 'Self-signed certificate',
                    'details': 'Certificate is self-signed'
                })

        except Exception as e:
            logger.error(f"Error checking certificate security: {e}")

        return issues

    def _check_ssl_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Check for common SSL/TLS vulnerabilities."""
        vulnerabilities = []

        if not target or target == 'localhost':
            return vulnerabilities

        try:
            # Check for common vulnerabilities using openssl if available
            openssl_checks = [
                {
                    'name': 'POODLE (SSL 3.0)',
                    'command': ['openssl', 's_client', '-connect', f'{target}:443', '-ssl3'],
                    'check_for': 'SSL3_GET_RECORD:wrong version number',
                    'severity': 'high'
                },
                {
                    'name': 'BEAST (TLS 1.0 CBC)',
                    'command': ['openssl', 's_client', '-connect', f'{target}:443', '-tls1'],
                    'check_for': 'BEGIN CERTIFICATE',
                    'severity': 'medium'
                }
            ]

            for vuln_check in openssl_checks:
                try:
                    result = subprocess.run(
                        vuln_check['command'],
                        input='Q\n',
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    if result.returncode == 0 and vuln_check['check_for'] in result.stdout:
                        vulnerabilities.append({
                            'name': vuln_check['name'],
                            'severity': vuln_check['severity'],
                            'detected': True,
                            'details': f"Service supports vulnerable configuration"
                        })

                except FileNotFoundError:
                    # OpenSSL not available
                    break
                except subprocess.TimeoutExpired:
                    continue
                except Exception as e:
                    logger.debug(f"Error checking {vuln_check['name']}: {e}")

        except Exception as e:
            logger.error(f"Error checking SSL vulnerabilities: {e}")

        return vulnerabilities

    def _assess_ssl_compliance(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess SSL/TLS compliance with security standards."""
        compliance = {
            'overall_score': 0,
            'issues': [],
            'recommendations': []
        }

        total_checks = 0
        passed_checks = 0

        try:
            # Check system certificate store
            cert_store = results.get('system_certificates', {})
            total_checks += 1
            if cert_store.get('store_accessible'):
                passed_checks += 1
            else:
                compliance['issues'].append('Certificate store not accessible')

            # Check for expired certificates
            if cert_store.get('expired_certificates'):
                compliance['issues'].append(f"{len(cert_store['expired_certificates'])} expired certificates found")
            else:
                passed_checks += 1
                total_checks += 1

            # Check services
            services = results.get('services', [])
            for service in services:
                total_checks += 2  # Protocol and certificate checks

                if service.get('accessible'):
                    passed_checks += 1

                    # Check protocol version
                    protocol = service.get('protocol_version', '')
                    if protocol and protocol not in ['SSLv2', 'SSLv3', 'TLSv1']:
                        passed_checks += 1
                    else:
                        compliance['issues'].append(f"Service {service['service']} uses weak protocol")

                # Check for security issues
                security_issues = service.get('security_issues', [])
                critical_issues = [i for i in security_issues if i.get('severity') == 'critical']
                if not critical_issues:
                    passed_checks += 1
                    total_checks += 1

            # Check vulnerabilities
            vulnerabilities = results.get('vulnerabilities', [])
            total_checks += 1
            if not vulnerabilities:
                passed_checks += 1
            else:
                compliance['issues'].append(f"{len(vulnerabilities)} SSL/TLS vulnerabilities detected")

            # Calculate overall score
            if total_checks > 0:
                compliance['overall_score'] = round((passed_checks / total_checks) * 100, 2)

        except Exception as e:
            logger.error(f"Error assessing SSL compliance: {e}")

        return compliance

    def _determine_overall_status(self, results: Dict[str, Any]) -> Tuple[str, str]:
        """Determine overall SSL/TLS security status."""
        compliance = results.get('compliance', {})
        score = compliance.get('overall_score', 0)

        vulnerabilities = results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']

        services = results.get('services', [])
        critical_service_issues = []
        for service in services:
            security_issues = service.get('security_issues', [])
            critical_service_issues.extend([i for i in security_issues if i.get('severity') == 'critical'])

        if critical_vulns or critical_service_issues:
            return 'fail', 'Critical SSL/TLS security issues detected'
        elif score < 60:
            return 'fail', f'SSL/TLS security score too low: {score}%'
        elif score < 80:
            return 'warning', f'SSL/TLS security needs improvement: {score}%'
        else:
            return 'pass', f'SSL/TLS security is adequate: {score}%'

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on SSL/TLS check results."""
        recommendations = []

        # System certificate store recommendations
        cert_store = results.get('system_certificates', {})
        if not cert_store.get('store_accessible'):
            recommendations.append("Ensure certificate store is accessible and properly configured")

        expired_certs = cert_store.get('expired_certificates', [])
        if expired_certs:
            recommendations.append(f"Remove or replace {len(expired_certs)} expired certificates")

        expiring_certs = cert_store.get('expiring_soon', [])
        if expiring_certs:
            recommendations.append(f"Renew {len(expiring_certs)} certificates expiring within 30 days")

        # Service-specific recommendations
        services = results.get('services', [])
        for service in services:
            service_issues = service.get('security_issues', [])
            for issue in service_issues:
                if issue.get('severity') in ['critical', 'high']:
                    recommendations.append(f"{service['service']}: {issue['issue']} - {issue['details']}")

        # Vulnerability recommendations
        vulnerabilities = results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln.get('detected'):
                recommendations.append(f"Address {vuln['name']} vulnerability")

        # General recommendations
        compliance = results.get('compliance', {})
        if compliance.get('overall_score', 0) < 80:
            recommendations.extend([
                "Upgrade to TLS 1.2 or higher for all services",
                "Disable weak cipher suites and protocols",
                "Implement proper certificate management procedures",
                "Regular security scanning and certificate monitoring"
            ])

        if not recommendations:
            recommendations.append("SSL/TLS configuration appears secure - maintain current security practices")

        return recommendations