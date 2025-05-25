"""
Firewall configuration check.

This module implements checks to verify firewall configuration and status
on Windows, Linux, and macOS systems.
"""

import logging
import subprocess
import json
import platform
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from ..base import BaseCheck, CheckResult, CheckStatus

logger = logging.getLogger(__name__)


class FirewallCheck(BaseCheck):
    """Check for firewall configuration and status."""

    def __init__(self):
        super().__init__()
        self.id = "firewall"
        self.name = "Firewall Configuration"
        self.description = "Verify that firewall is enabled and properly configured"
        self.category = "network"
        self.severity = "high"
        self.supported_os = ["windows", "linux", "macos"]

    def is_applicable(self, context: Dict[str, Any]) -> bool:
        os_type = context.get("os_type", "").lower()
        return os_type in ["windows", "linux", "macos"]

    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Execute the firewall check.

        Args:
            context: Execution context containing OS info and other details

        Returns:
            CheckResult with the firewall status
        """
        try:
            os_type = context.get('os_type', platform.system().lower())

            if os_type == 'windows':
                return self._check_windows_firewall()
            elif os_type == 'linux':
                return self._check_linux_firewall()
            elif os_type == 'darwin':  # macOS
                return self._check_macos_firewall()
            else:
                return self._create_error_result(f"Unsupported OS: {os_type}")

        except Exception as e:
            logger.error(f"Error in firewall check: {str(e)}")
            return self._create_error_result(str(e))

    def _check_windows_firewall(self) -> CheckResult:
        """Check Windows Firewall status."""
        results = {
            'profiles': {},
            'rules_count': 0,
            'default_policy': {},
            'status': 'unknown'
        }

        try:
            # Check firewall status using netsh
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                profiles = self._parse_windows_firewall_profiles(result.stdout)
                results['profiles'] = profiles

                # Check if all profiles are enabled
                all_enabled = all(
                    profile.get('state', '').lower() == 'on'
                    for profile in profiles.values()
                )

                if all_enabled:
                    results['status'] = 'enabled'
                    status = "pass"
                    message = "Windows Firewall is enabled on all profiles"
                else:
                    results['status'] = 'partially_enabled'
                    status = "warning"
                    message = "Windows Firewall is not enabled on all profiles"

                # Get firewall rules count
                rules_result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if rules_result.returncode == 0:
                    rules_count = len([line for line in rules_result.stdout.split('\n')
                                       if 'Rule Name:' in line])
                    results['rules_count'] = rules_count

            else:
                results['status'] = 'error'
                status = "fail"
                message = "Unable to check Windows Firewall status"

        except subprocess.TimeoutExpired:
            results['status'] = 'timeout'
            status = "error"
            message = "Timeout while checking Windows Firewall"
        except Exception as e:
            logger.error(f"Error checking Windows firewall: {str(e)}")
            results['status'] = 'error'
            status = "error"
            message = f"Error checking Windows Firewall: {str(e)}"

        return CheckResult(
            status=CheckStatus(status),
            message=message,
            details=results,
            recommendations=self._get_windows_firewall_recommendations(results)
        )

    def _check_linux_firewall(self) -> CheckResult:
        """Check Linux firewall status (iptables, ufw, firewalld)."""
        results = {
            'firewall_type': None,
            'status': 'unknown',
            'rules_count': 0,
            'details': {}
        }

        # Check for different firewall systems
        firewall_systems = [
            ('ufw', self._check_ufw),
            ('firewalld', self._check_firewalld),
            ('iptables', self._check_iptables)
        ]

        for fw_name, check_func in firewall_systems:
            try:
                fw_result = check_func()
                if fw_result['detected']:
                    results['firewall_type'] = fw_name
                    results.update(fw_result)
                    break
            except Exception as e:
                logger.debug(f"Error checking {fw_name}: {str(e)}")
                continue

        # Determine overall status
        if results['firewall_type']:
            if results['status'] == 'active':
                status = "pass"
                message = f"Firewall ({results['firewall_type']}) is active and configured"
            elif results['status'] == 'inactive':
                status = "fail"
                message = f"Firewall ({results['firewall_type']}) is installed but inactive"
            else:
                status = "warning"
                message = f"Firewall ({results['firewall_type']}) status unclear"
        else:
            status = "fail"
            message = "No firewall detected or all firewalls are inactive"

        return CheckResult(
            status=CheckStatus(status),
            message=message,
            details=results,
            recommendations=self._get_linux_firewall_recommendations(results)
        )

    def _check_macos_firewall(self) -> CheckResult:
        """Check macOS Application Firewall status."""
        results = {
            'application_firewall': False,
            'stealth_mode': False,
            'logging': False,
            'status': 'unknown'
        }

        try:
            # Check Application Firewall status
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                if "enabled" in result.stdout.lower():
                    results['application_firewall'] = True
                    results['status'] = 'enabled'
                else:
                    results['application_firewall'] = False
                    results['status'] = 'disabled'

                # Check stealth mode
                stealth_result = subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if stealth_result.returncode == 0:
                    results['stealth_mode'] = "enabled" in stealth_result.stdout.lower()

                # Check logging
                logging_result = subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getloggingmode"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if logging_result.returncode == 0:
                    results['logging'] = "enabled" in logging_result.stdout.lower()

            # Determine status
            if results['application_firewall']:
                status = "pass"
                message = "macOS Application Firewall is enabled"
            else:
                status = "fail"
                message = "macOS Application Firewall is disabled"

        except Exception as e:
            logger.error(f"Error checking macOS firewall: {str(e)}")
            status = "error"
            message = f"Error checking macOS firewall: {str(e)}"

        return CheckResult(
            status=CheckStatus(status),
            message=message,
            details=results,
            recommendations=self._get_macos_firewall_recommendations(results)
        )

    def _parse_windows_firewall_profiles(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse Windows firewall profiles from netsh output."""
        profiles = {}
        current_profile = None

        for line in output.split('\n'):
            line = line.strip()

            if 'Profile Settings:' in line:
                # Extract profile name
                profile_match = re.search(r'Profile Settings:\s*(.+)', line)
                if profile_match:
                    current_profile = profile_match.group(1).strip()
                    profiles[current_profile] = {}
            elif current_profile and ':' in line:
                # Parse key-value pairs
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    profiles[current_profile][key] = value

        return profiles

    def _check_ufw(self) -> Dict[str, Any]:
        """Check UFW (Uncomplicated Firewall) status."""
        try:
            result = subprocess.run(
                ["ufw", "status", "verbose"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                if "Status: active" in output:
                    status = 'active'
                elif "Status: inactive" in output:
                    status = 'inactive'
                else:
                    status = 'unknown'

                # Count rules
                rules_count = len([line for line in output.split('\n')
                                   if '-->' in line or 'ALLOW' in line or 'DENY' in line])

                return {
                    'detected': True,
                    'status': status,
                    'rules_count': rules_count,
                    'raw_output': output
                }
            else:
                return {'detected': False}

        except FileNotFoundError:
            return {'detected': False}
        except Exception as e:
            logger.error(f"Error checking UFW: {str(e)}")
            return {'detected': False}

    def _check_firewalld(self) -> Dict[str, Any]:
        """Check firewalld status."""
        try:
            # Check if firewalld is running
            result = subprocess.run(
                ["systemctl", "is-active", "firewalld"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and "active" in result.stdout:
                status = 'active'

                # Get zone information
                zones_result = subprocess.run(
                    ["firewall-cmd", "--get-active-zones"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                zones = zones_result.stdout if zones_result.returncode == 0 else ""

                # Get rules count (approximate)
                rules_result = subprocess.run(
                    ["firewall-cmd", "--list-all"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                rules_count = 0
                if rules_result.returncode == 0:
                    rules_count = len([line for line in rules_result.stdout.split('\n')
                                       if 'services:' in line or 'ports:' in line])

                return {
                    'detected': True,
                    'status': status,
                    'zones': zones,
                    'rules_count': rules_count
                }
            else:
                return {
                    'detected': True,
                    'status': 'inactive'
                }

        except FileNotFoundError:
            return {'detected': False}
        except Exception as e:
            logger.error(f"Error checking firewalld: {str(e)}")
            return {'detected': False}

    def _check_iptables(self) -> Dict[str, Any]:
        """Check iptables status."""
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Count rules (excluding default chains)
                lines = output.split('\n')
                rules_count = len([line for line in lines
                                   if line and not line.startswith('Chain')
                                   and not line.startswith('target')])

                # Determine if iptables has meaningful rules
                if rules_count > 3:  # More than just default policies
                    status = 'active'
                else:
                    status = 'default'  # Default rules only

                return {
                    'detected': True,
                    'status': status,
                    'rules_count': rules_count,
                    'raw_output': output
                }
            else:
                return {'detected': False}

        except FileNotFoundError:
            return {'detected': False}
        except Exception as e:
            logger.error(f"Error checking iptables: {str(e)}")
            return {'detected': False}

    def _get_windows_firewall_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Get recommendations for Windows firewall configuration."""
        recommendations = []

        if results['status'] == 'error':
            recommendations.append("Unable to check firewall status - verify Windows Firewall service")
        elif results['status'] == 'partially_enabled':
            recommendations.append("Enable Windows Firewall on all network profiles")
        elif results['status'] != 'enabled':
            recommendations.append("Enable Windows Firewall")

        if results.get('rules_count', 0) == 0:
            recommendations.append("Configure appropriate firewall rules for your network requirements")

        # Check specific profiles
        profiles = results.get('profiles', {})
        for profile_name, profile_data in profiles.items():
            state = profile_data.get('State', '').lower()
            if state != 'on':
                recommendations.append(f"Enable firewall for {profile_name} profile")

        if not recommendations:
            recommendations.append("Firewall configuration appears secure")

        return recommendations

    def _get_linux_firewall_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Get recommendations for Linux firewall configuration."""
        recommendations = []

        if not results.get('firewall_type'):
            recommendations.append("Install and configure a firewall (ufw, firewalld, or iptables)")
        elif results.get('status') == 'inactive':
            fw_type = results['firewall_type']
            if fw_type == 'ufw':
                recommendations.append("Enable UFW firewall: sudo ufw enable")
            elif fw_type == 'firewalld':
                recommendations.append("Start and enable firewalld: sudo systemctl enable --now firewalld")
            elif fw_type == 'iptables':
                recommendations.append("Configure iptables rules and ensure they persist after reboot")

        if results.get('rules_count', 0) == 0:
            recommendations.append("Configure firewall rules to control network access")

        if not recommendations:
            recommendations.append("Firewall configuration appears adequate")

        return recommendations

    def _get_macos_firewall_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Get recommendations for macOS firewall configuration."""
        recommendations = []

        if not results.get('application_firewall'):
            recommendations.append("Enable macOS Application Firewall in System Preferences > Security & Privacy")

        if not results.get('stealth_mode'):
            recommendations.append("Consider enabling Stealth Mode for additional security")

        if not results.get('logging'):
            recommendations.append("Enable firewall logging to monitor connection attempts")

        if not recommendations:
            recommendations.append("macOS firewall configuration appears secure")

        return recommendations

    def _create_error_result(self, error_message: str) -> CheckResult:
        """Create an error result."""
        return CheckResult(
            status=CheckStatus.ERROR,
            message=error_message,
            details={"error": error_message}
        )