"""
Open ports check.

This module implements checks to detect and verify open network ports
on the system, identifying potential security risks.
"""

import logging
import subprocess
import socket
import json
import platform
import re
from typing import Dict, Any, List, Optional, Tuple, Set
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base import BaseCheck, CheckResult

logger = logging.getLogger(__name__)


class OpenPortsCheck(BaseCheck):
    """Check for open network ports and assess associated risks."""

    def __init__(self):
        super().__init__()
        self.id = "open_ports"
        self.name = "Open Network Ports"
        self.description = "Identify and verify open network ports and assess security risks"
        self.category = "network"
        self.severity = "high"
        self.supported_os = ["windows", "linux", "macos"]

        # Well-known ports that might pose security risks if open
        self.risky_ports = {
            21: {"service": "FTP", "risk": "high"},
            22: {"service": "SSH", "risk": "medium"},
            23: {"service": "Telnet", "risk": "high"},
            25: {"service": "SMTP", "risk": "medium"},
            53: {"service": "DNS", "risk": "medium"},
            135: {"service": "RPC", "risk": "high"},
            137: {"service": "NetBIOS", "risk": "high"},
            138: {"service": "NetBIOS", "risk": "high"},
            139: {"service": "NetBIOS", "risk": "high"},
            161: {"service": "SNMP", "risk": "medium"},
            445: {"service": "SMB", "risk": "high"},
            1433: {"service": "MS SQL", "risk": "medium"},
            1434: {"service": "MS SQL Browser", "risk": "medium"},
            3306: {"service": "MySQL", "risk": "medium"},
            3389: {"service": "RDP", "risk": "high"},
            5432: {"service": "PostgreSQL", "risk": "medium"},
            5900: {"service": "VNC", "risk": "high"},
            8080: {"service": "HTTP Alternate", "risk": "medium"},
        }

        # Common essential ports that are typically safer
        self.common_safe_ports = {
            80: {"service": "HTTP", "risk": "low"},
            443: {"service": "HTTPS", "risk": "low"},
            5353: {"service": "mDNS", "risk": "low"},
            631: {"service": "CUPS", "risk": "low"}
        }

    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Execute the open ports check.

        Args:
            context: Execution context containing OS info and other details

        Returns:
            CheckResult with the open ports status
        """
        try:
            os_type = context.get('os_type', platform.system().lower())

            # First, identify all open ports using the OS-specific method
            open_ports = self._get_open_ports(os_type)

            # Then analyze the open ports for potential security risks
            analysis = self._analyze_open_ports(open_ports)

            # Determine overall status
            status, message = self._assess_overall_status(analysis)

            # Prepare the results
            results = {
                'open_ports': open_ports,
                'analysis': analysis,
                'status': status
            }

            return CheckResult(
                check_id=self.id,
                name=self.name,
                status=status,
                severity=self.severity,
                message=message,
                details=results,
                recommendations=self._get_recommendations(open_ports, analysis)
            )

        except Exception as e:
            logger.error(f"Error in open ports check: {str(e)}")
            return self._create_error_result(str(e))

    def _get_open_ports(self, os_type: str) -> List[Dict[str, Any]]:
        """
        Get a list of open ports using OS-specific methods.

        Args:
            os_type: Operating system type

        Returns:
            List of dictionaries containing port information
        """
        if os_type == 'windows':
            return self._get_windows_open_ports()
        elif os_type == 'linux':
            return self._get_linux_open_ports()
        elif os_type == 'darwin':  # macOS
            return self._get_macos_open_ports()
        else:
            logger.warning(f"Unsupported OS for port checking: {os_type}")
            return []

    def _get_windows_open_ports(self) -> List[Dict[str, Any]]:
        """Get open ports on Windows systems."""
        open_ports = []

        try:
            # Use netstat to get listening ports
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse netstat output
                for line in output.splitlines():
                    line = line.strip()

                    # Look for TCP and UDP entries in LISTENING state
                    if ("TCP" in line and "LISTENING" in line) or "UDP" in line:
                        parts = re.split(r'\s+', line)

                        if len(parts) >= 4:
                            protocol = parts[0].lower()  # tcp or udp
                            local_address = parts[1]
                            pid = parts[-1] if "LISTENING" in line else parts[-1]

                            # Extract IP and port
                            ip_port = local_address.split(':')
                            if len(ip_port) >= 2:
                                ip = ip_port[0]

                                # Handle IPv6 addresses
                                if '[' in ip:
                                    # Extract port from the end of the string
                                    port_match = re.search(r']:(\d+)$', local_address)
                                    if port_match:
                                        port = int(port_match.group(1))
                                    else:
                                        continue
                                else:
                                    port = int(ip_port[-1])

                                # Get process name from PID
                                process_name = self._get_windows_process_name(pid)

                                # Add port to results
                                open_ports.append({
                                    'port': port,
                                    'protocol': protocol,
                                    'local_address': local_address,
                                    'process': process_name,
                                    'pid': pid
                                })

            # Alternative method using PowerShell in case netstat fails
            if not open_ports:
                open_ports = self._get_windows_open_ports_powershell()

            return open_ports

        except Exception as e:
            logger.error(f"Error getting Windows open ports: {str(e)}")

            # Try alternative method
            return self._get_windows_open_ports_powershell()

    def _get_windows_process_name(self, pid: str) -> str:
        """Get process name from PID on Windows."""
        try:
            ps_command = f"""
            Get-Process -Id {pid} -ErrorAction SilentlyContinue | 
            Select-Object -Property ProcessName | 
            ConvertTo-Json
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout.strip():
                process_data = json.loads(result.stdout)
                return process_data.get('ProcessName', 'Unknown')

            return f"Unknown ({pid})"

        except Exception:
            return f"Unknown ({pid})"

    def _get_windows_open_ports_powershell(self) -> List[Dict[str, Any]]:
        """Get open ports on Windows using PowerShell."""
        open_ports = []

        try:
            ps_command = """
            Get-NetTCPConnection -State Listen | 
            Select-Object LocalPort, LocalAddress, OwningProcess | 
            ConvertTo-Json
            """

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout.strip():
                tcp_connections = json.loads(result.stdout)

                # Handle case when only one connection is found
                if isinstance(tcp_connections, dict):
                    tcp_connections = [tcp_connections]

                for conn in tcp_connections:
                    pid = str(conn.get('OwningProcess', ''))
                    process_name = self._get_windows_process_name(pid)

                    open_ports.append({
                        'port': conn.get('LocalPort'),
                        'protocol': 'tcp',
                        'local_address': conn.get('LocalAddress', '0.0.0.0'),
                        'process': process_name,
                        'pid': pid
                    })

            # Get UDP connections
            ps_command_udp = """
            Get-NetUDPEndpoint | 
            Select-Object LocalPort, LocalAddress, OwningProcess | 
            ConvertTo-Json
            """

            result_udp = subprocess.run(
                ["powershell", "-Command", ps_command_udp],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result_udp.returncode == 0 and result_udp.stdout.strip():
                udp_endpoints = json.loads(result_udp.stdout)

                # Handle case when only one endpoint is found
                if isinstance(udp_endpoints, dict):
                    udp_endpoints = [udp_endpoints]

                for endpoint in udp_endpoints:
                    pid = str(endpoint.get('OwningProcess', ''))
                    process_name = self._get_windows_process_name(pid)

                    open_ports.append({
                        'port': endpoint.get('LocalPort'),
                        'protocol': 'udp',
                        'local_address': endpoint.get('LocalAddress', '0.0.0.0'),
                        'process': process_name,
                        'pid': pid
                    })

            return open_ports

        except Exception as e:
            logger.error(f"Error getting Windows open ports with PowerShell: {str(e)}")
            return []

    def _get_linux_open_ports(self) -> List[Dict[str, Any]]:
        """Get open ports on Linux systems."""
        open_ports = []

        # Try ss command first (newer systems)
        ss_result = self._get_linux_open_ports_ss()
        if ss_result:
            return ss_result

        # Fall back to netstat if ss fails
        try:
            # Use netstat to get listening ports
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse netstat output
                for line in output.splitlines():
                    line = line.strip()

                    # Look for lines with "LISTEN"
                    if "LISTEN" in line:
                        parts = re.split(r'\s+', line)

                        if len(parts) >= 6:
                            protocol = parts[0].lower()  # tcp or udp
                            local_address = parts[3]

                            # Extract IP and port
                            ip_port = local_address.rsplit(':', 1)
                            if len(ip_port) == 2:
                                ip = ip_port[0]
                                port = int(ip_port[1])

                                # Get process info
                                process_info = self._get_linux_process_for_port(port, protocol)

                                # Add port to results
                                open_ports.append({
                                    'port': port,
                                    'protocol': protocol,
                                    'local_address': local_address,
                                    'process': process_info.get('name', 'Unknown'),
                                    'pid': process_info.get('pid', '')
                                })

            return open_ports

        except Exception as e:
            logger.error(f"Error getting Linux open ports: {str(e)}")
            return []

    def _get_linux_open_ports_ss(self) -> List[Dict[str, Any]]:
        """Get open ports on Linux systems using ss command."""
        open_ports = []

        try:
            # Use ss to get listening ports (newer systems)
            result = subprocess.run(
                ["ss", "-tuln"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse ss output
                for line in output.splitlines():
                    line = line.strip()

                    # Skip header line
                    if line.startswith("Netid") or not line:
                        continue

                    parts = re.split(r'\s+', line)

                    if len(parts) >= 5:
                        protocol = parts[0].lower()  # tcp or udp
                        local_address = parts[4]

                        # Extract IP and port
                        ip_port = local_address.rsplit(':', 1)
                        if len(ip_port) == 2:
                            ip = ip_port[0]
                            port = int(ip_port[1])

                            # Get process info
                            process_info = self._get_linux_process_for_port(port, protocol)

                            # Add port to results
                            open_ports.append({
                                'port': port,
                                'protocol': protocol,
                                'local_address': local_address,
                                'process': process_info.get('name', 'Unknown'),
                                'pid': process_info.get('pid', '')
                            })

            return open_ports

        except Exception as e:
            logger.debug(f"Error getting Linux open ports with ss: {str(e)}")
            return []

    def _get_linux_process_for_port(self, port: int, protocol: str) -> Dict[str, str]:
        """Get process information for a port on Linux."""
        try:
            # Use lsof to find process
            result = subprocess.run(
                ["lsof", f"-i{protocol}:{port}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse lsof output
                for line in output.splitlines():
                    if "LISTEN" in line or protocol == "udp":
                        parts = re.split(r'\s+', line)

                        if len(parts) >= 2:
                            return {
                                'name': parts[0],
                                'pid': parts[1]
                            }

            return {'name': 'Unknown', 'pid': ''}

        except Exception:
            return {'name': 'Unknown', 'pid': ''}

    def _get_macos_open_ports(self) -> List[Dict[str, Any]]:
        """Get open ports on macOS systems."""
        open_ports = []

        try:
            # Use lsof to get listening ports
            result = subprocess.run(
                ["lsof", "-i", "-P", "-n"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                output = result.stdout

                # Parse lsof output
                for line in output.splitlines():
                    if "LISTEN" in line or "UDP" in line:
                        parts = re.split(r'\s+', line)

                        if len(parts) >= 9:
                            process = parts[0]
                            pid = parts[1]
                            protocol = parts[7].lower()  # TCP or UDP
                            local_address = parts[8].split('->')[0] if '->' in parts[8] else parts[8]

                            # Extract port from address (format: IP:port)
                            ip_port_match = re.search(r'(.*):(\d+)$', local_address)
                            if ip_port_match:
                                ip = ip_port_match.group(1)
                                port = int(ip_port_match.group(2))

                                # Add port to results
                                open_ports.append({
                                    'port': port,
                                    'protocol': 'tcp' if 'TCP' in protocol else 'udp',
                                    'local_address': local_address,
                                    'process': process,
                                    'pid': pid
                                })

            return open_ports

        except Exception as e:
            logger.error(f"Error getting macOS open ports: {str(e)}")
            return []

    def _analyze_open_ports(self, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze open ports for security risks.

        Args:
            open_ports: List of open ports with details

        Returns:
            Analysis results with risk categorization
        """
        analysis = {
            'total_open_ports': len(open_ports),
            'high_risk_ports': [],
            'medium_risk_ports': [],
            'low_risk_ports': [],
            'internet_exposed': False,
            'public_services': []
        }

        # Check for internet-exposed interfaces
        internet_exposed = False
        for port in open_ports:
            local_address = port.get('local_address', '')

            # Check if the port is bound to all interfaces (0.0.0.0 or ::)
            if '0.0.0.0' in local_address or '::' in local_address:
                port_num = port.get('port')

                # Check if it's a commonly exposed service
                if port_num in [80, 443, 22, 25, 53]:
                    analysis['public_services'].append({
                        'port': port_num,
                        'protocol': port.get('protocol', ''),
                        'process': port.get('process', 'Unknown')
                    })

                internet_exposed = True

        analysis['internet_exposed'] = internet_exposed

        # Categorize ports by risk level
        for port in open_ports:
            port_num = port.get('port')

            if port_num in self.risky_ports:
                risk_info = self.risky_ports[port_num].copy()
                risk_info.update({
                    'port': port_num,
                    'protocol': port.get('protocol', ''),
                    'process': port.get('process', 'Unknown')
                })

                if risk_info['risk'] == 'high':
                    analysis['high_risk_ports'].append(risk_info)
                elif risk_info['risk'] == 'medium':
                    analysis['medium_risk_ports'].append(risk_info)
            elif port_num in self.common_safe_ports:
                risk_info = self.common_safe_ports[port_num].copy()
                risk_info.update({
                    'port': port_num,
                    'protocol': port.get('protocol', ''),
                    'process': port.get('process', 'Unknown')
                })

                analysis['low_risk_ports'].append(risk_info)
            else:
                # Unknown port, consider it low risk unless it's exposed
                risk_level = 'medium' if port.get('local_address', '').startswith('0.0.0.0') else 'low'

                risk_info = {
                    'port': port_num,
                    'protocol': port.get('protocol', ''),
                    'process': port.get('process', 'Unknown'),
                    'service': 'Unknown',
                    'risk': risk_level
                }

                if risk_level == 'medium':
                    analysis['medium_risk_ports'].append(risk_info)
                else:
                    analysis['low_risk_ports'].append(risk_info)

        return analysis

    def _assess_overall_status(self, analysis: Dict[str, Any]) -> Tuple[str, str]:
        """
        Assess the overall security status based on open ports analysis.

        Args:
            analysis: Analysis results

        Returns:
            Tuple of (status, message)
        """
        high_risk_count = len(analysis.get('high_risk_ports', []))
        medium_risk_count = len(analysis.get('medium_risk_ports', []))
        internet_exposed = analysis.get('internet_exposed', False)

        if high_risk_count > 0:
            status = "fail"
            message = f"Found {high_risk_count} high-risk open ports that may pose security threats"
        elif medium_risk_count > 0 and internet_exposed:
            status = "warning"
            message = f"Found {medium_risk_count} medium-risk open ports with potential internet exposure"
        elif medium_risk_count > 0:
            status = "warning"
            message = f"Found {medium_risk_count} medium-risk open ports"
        elif internet_exposed:
            status = "warning"
            message = "System has ports exposed to all network interfaces"
        else:
            status = "pass"
            message = "No high-risk open ports detected"

        return status, message

    def _get_recommendations(self, open_ports: List[Dict[str, Any]], analysis: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations based on open ports and analysis.

        Args:
            open_ports: List of open ports
            analysis: Analysis results

        Returns:
            List of recommendations
        """
        recommendations = []

        # Recommendations for high-risk ports
        high_risk_ports = analysis.get('high_risk_ports', [])
        if high_risk_ports:
            recommendations.append("Close or restrict access to the following high-risk ports:")

            for port_info in high_risk_ports:
                port = port_info.get('port')
                service = port_info.get('service', 'Unknown')
                process = port_info.get('process', 'Unknown')

                recommendations.append(f"  - Port {port} ({service}) used by process '{process}'")

        # Recommendations for internet-exposed services
        if analysis.get('internet_exposed', False):
            # Check for sensitive services exposed to the internet
            exposed_sensitive = [p for p in open_ports if
                                 p.get('port') in [22, 3389, 1433, 3306, 5432, 21, 23, 137, 138, 139, 445] and
                                 ('0.0.0.0' in p.get('local_address', '') or '::' in p.get('local_address', ''))]

            if exposed_sensitive:
                recommendations.append(
                    "Restrict the following sensitive services to specific IP addresses or VPN access:")

                for port in exposed_sensitive:
                    port_num = port.get('port')
                    service = self.risky_ports.get(port_num, {}).get('service', 'Unknown')
                    recommendations.append(f"  - Port {port_num} ({service})")

            recommendations.append(
                "Bind services to specific IP addresses instead of 0.0.0.0 (all interfaces) when possible")

        # General recommendations
        if open_ports:
            recommendations.append("Use a firewall to restrict access to necessary ports only")
            recommendations.append("Regularly audit open ports and disable unnecessary services")

        # If no specific recommendations
        if not recommendations:
            recommendations.append("Port configuration appears to be secure")

        return recommendations