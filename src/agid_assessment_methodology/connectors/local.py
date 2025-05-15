"""Local connector for local system assessment.

This module provides functionality for assessing the local system
without requiring remote connections.
"""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import psutil

from agid_assessment_methodology.core.engine import Target, TargetType
from agid_assessment_methodology.utils.exceptions import ConnectionError

logger = logging.getLogger(__name__)


class LocalConnector:
    """Local connector for local system assessment."""

    def __init__(self, target: Optional[Target] = None):
        """Initialize the local connector.

        Args:
            target: Target system info (optional, will be created if not provided)
        """
        self.target = target or self._create_local_target()
        self._validate_target()
        logger.debug(f"Initialized local connector for target: {self.target.name}")

    def _create_local_target(self) -> Target:
        """Create a target for the local system.

        Returns:
            Target for the local system
        """
        system = platform.system().lower()
        if system == "windows":
            target_type = TargetType.WINDOWS
        elif system == "linux":
            target_type = TargetType.LINUX
        else:
            target_type = TargetType.LOCAL

        return Target(
            name="localhost",
            host="localhost",
            type=target_type,
        )

    def _validate_target(self) -> None:
        """Validate the target configuration."""
        if self.target.type not in [TargetType.LOCAL, TargetType.WINDOWS, TargetType.LINUX]:
            raise ConnectionError(
                f"LocalConnector requires a 'local', 'windows', or 'linux' target type, got '{self.target.type}'")

        if self.target.host != "localhost":
            raise ConnectionError(f"LocalConnector requires a 'localhost' host, got '{self.target.host}'")

    def is_windows(self) -> bool:
        """Check if the local system is Windows.

        Returns:
            True if the local system is Windows, False otherwise
        """
        return platform.system().lower() == "windows"

    def is_linux(self) -> bool:
        """Check if the local system is Linux.

        Returns:
            True if the local system is Linux, False otherwise
        """
        return platform.system().lower() == "linux"

    def execute_command(
        self,
        command: Union[str, List[str]],
        shell: bool = False,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """Execute a command on the local system.

        Args:
            command: Command to execute (string or list of arguments)
            shell: Whether to use shell execution
            timeout: Command timeout in seconds, or None for no timeout
            cwd: Working directory for the command
            env: Environment variables for the command

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            logger.debug(f"Executing command on {self.target.name}: {command}")

            # Execute the command
            process = subprocess.Popen(
                command,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                universal_newlines=True,
            )

            # Wait for the command to complete
            stdout, stderr = process.communicate(timeout=timeout)
            exit_code = process.returncode

            logger.debug(f"Command exit code: {exit_code}")
            return exit_code, stdout, stderr

        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            stdout, stderr = process.communicate()
            raise ConnectionError(f"Command timed out after {timeout} seconds")

        except Exception as e:
            raise ConnectionError(f"Error executing command on {self.target.name}: {e}")

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the local system.

        Args:
            path: Path to the file

        Returns:
            True if the file exists, False otherwise
        """
        try:
            logger.debug(f"Checking if file exists on {self.target.name}: {path}")
            return os.path.exists(path)

        except Exception as e:
            logger.warning(f"Error checking if file exists on {self.target.name}: {e}")
            return False

    def read_file(self, path: str) -> str:
        """Read a file from the local system.

        Args:
            path: Path to the file

        Returns:
            File contents
        """
        try:
            logger.debug(f"Reading file from {self.target.name}: {path}")

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            return content

        except Exception as e:
            raise ConnectionError(f"Error reading file from {self.target.name}: {e}")

    def read_file_binary(self, path: str) -> bytes:
        """Read a binary file from the local system.

        Args:
            path: Path to the file

        Returns:
            File contents as bytes
        """
        try:
            logger.debug(f"Reading binary file from {self.target.name}: {path}")

            with open(path, "rb") as f:
                content = f.read()

            return content

        except Exception as e:
            raise ConnectionError(f"Error reading binary file from {self.target.name}: {e}")

    def write_file(self, path: str, content: str) -> None:
        """Write a file to the local system.

        Args:
            path: Path to the file
            content: File contents
        """
        try:
            logger.debug(f"Writing file to {self.target.name}: {path}")

            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

        except Exception as e:
            raise ConnectionError(f"Error writing file to {self.target.name}: {e}")

    def write_file_binary(self, path: str, content: bytes) -> None:
        """Write a binary file to the local system.

        Args:
            path: Path to the file
            content: File contents as bytes
        """
        try:
            logger.debug(f"Writing binary file to {self.target.name}: {path}")

            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

            with open(path, "wb") as f:
                f.write(content)

        except Exception as e:
            raise ConnectionError(f"Error writing binary file to {self.target.name}: {e}")

    def list_directory(self, path: str) -> List[str]:
        """List files in a directory on the local system.

        Args:
            path: Path to the directory

        Returns:
            List of filenames
        """
        try:
            logger.debug(f"Listing directory on {self.target.name}: {path}")
            return os.listdir(path)

        except Exception as e:
            raise ConnectionError(f"Error listing directory on {self.target.name}: {e}")

    def get_file_stats(self, path: str) -> Dict[str, any]:
        """Get file statistics on the local system.

        Args:
            path: Path to the file

        Returns:
            Dictionary of file statistics
        """
        try:
            logger.debug(f"Getting file stats on {self.target.name}: {path}")
            stats = os.stat(path)

            return {
                "size": stats.st_size,
                "uid": stats.st_uid,
                "gid": stats.st_gid,
                "mode": stats.st_mode,
                "atime": stats.st_atime,
                "mtime": stats.st_mtime,
                "ctime": stats.st_ctime,
            }

        except Exception as e:
            raise ConnectionError(f"Error getting file stats on {self.target.name}: {e}")

    def get_system_info(self) -> Dict[str, any]:
        """Get system information from the local system.

        Returns:
            Dictionary of system information
        """
        try:
            logger.debug(f"Getting system information on {self.target.name}")

            # Get system information
            uname = platform.uname()
            boot_time = psutil.boot_time()

            # Build the result
            result = {
                "system": uname.system,
                "node": uname.node,
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
                "processor": uname.processor,
                "boot_time": boot_time,
                "python_version": platform.python_version(),
                "cpu_count": psutil.cpu_count(logical=False),
                "cpu_count_logical": psutil.cpu_count(logical=True),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
            }

            return result

        except Exception as e:
            raise ConnectionError(f"Error getting system information on {self.target.name}: {e}")

    def get_process_list(self) -> List[Dict[str, any]]:
        """Get a list of running processes on the local system.

        Returns:
            List of dictionaries containing process information
        """
        try:
            logger.debug(f"Getting process list on {self.target.name}")

            # Get all processes
            process_list = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time', 'memory_info']):
                try:
                    # Get process information
                    proc_info = proc.info

                    # Add process information to the list
                    process_list.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "username": proc_info['username'],
                        "cmdline": proc_info['cmdline'],
                        "create_time": proc_info['create_time'],
                        "memory_rss": proc_info['memory_info'].rss if proc_info['memory_info'] else None,
                        "memory_vms": proc_info['memory_info'].vms if proc_info['memory_info'] else None,
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Skip this process
                    pass

            return process_list

        except Exception as e:
            raise ConnectionError(f"Error getting process list on {self.target.name}: {e}")

    def get_service_list(self) -> List[Dict[str, any]]:
        """Get a list of services on the local system.

        Returns:
            List of dictionaries containing service information
        """
        if not self.is_windows():
            # Only supported on Windows
            logger.warning("get_service_list is only supported on Windows")
            return []

        try:
            logger.debug(f"Getting service list on {self.target.name}")

            # This is a Windows-specific operation
            # Use 'sc query' to get service information
            exit_code, stdout, stderr = self.execute_command("sc query state= all", shell=True)

            if exit_code != 0:
                raise ConnectionError(f"Error getting service list: {stderr}")

            # Parse the output
            services = []
            current_service = None

            for line in stdout.splitlines():
                line = line.strip()

                if line.startswith("SERVICE_NAME:"):
                    # New service
                    if current_service:
                        services.append(current_service)

                    current_service = {
                        "name": line.split(":", 1)[1].strip(),
                        "display_name": "",
                        "type": "",
                        "state": "",
                        "pid": None,
                    }

                elif line.startswith("DISPLAY_NAME:") and current_service:
                    current_service["display_name"] = line.split(":", 1)[1].strip()

                elif line.startswith("TYPE") and current_service:
                    current_service["type"] = line.split(":", 1)[1].strip()

                elif line.startswith("STATE") and current_service:
                    current_service["state"] = line.split(":", 1)[1].strip()

                elif line.startswith("PID") and current_service:
                    try:
                        current_service["pid"] = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        current_service["pid"] = None

            # Add the last service
            if current_service:
                services.append(current_service)

            return services

        except Exception as e:
            raise ConnectionError(f"Error getting service list on {self.target.name}: {e}")

    def get_network_connections(self) -> List[Dict[str, any]]:
        """Get a list of network connections on the local system.

        Returns:
            List of dictionaries containing network connection information
        """
        try:
            logger.debug(f"Getting network connections on {self.target.name}")

            # Get all network connections
            connections = []
            for conn in psutil.net_connections():
                try:
                    # Get connection information
                    connection = {
                        "fd": conn.fd,
                        "family": conn.family,
                        "type": conn.type,
                        "laddr": {
                            "ip": conn.laddr.ip if conn.laddr else None,
                            "port": conn.laddr.port if conn.laddr else None,
                        },
                        "raddr": {
                            "ip": conn.raddr.ip if conn.raddr else None,
                            "port": conn.raddr.port if conn.raddr else None,
                        },
                        "status": conn.status,
                        "pid": conn.pid,
                    }

                    # Add connection to the list
                    connections.append(connection)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Skip this connection
                    pass

            return connections

        except Exception as e:
            raise ConnectionError(f"Error getting network connections on {self.target.name}: {e}")

    def get_installed_software(self) -> List[Dict[str, any]]:
        """Get a list of installed software on the local system.

        Returns:
            List of dictionaries containing software information
        """
        if self.is_windows():
            return self._get_installed_software_windows()
        elif self.is_linux():
            return self._get_installed_software_linux()
        else:
            logger.warning("get_installed_software is not supported on this platform")
            return []

    def _get_installed_software_windows(self) -> List[Dict[str, any]]:
        """Get a list of installed software on Windows.

        Returns:
            List of dictionaries containing software information
        """
        try:
            logger.debug(f"Getting installed software on {self.target.name} (Windows)")

            # Use PowerShell to get installed software
            script = """
            Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate | ConvertTo-Csv -NoTypeInformation
            """

            exit_code, stdout, stderr = self.execute_command(["powershell", "-Command", script])

            if exit_code != 0:
                raise ConnectionError(f"Error getting installed software: {stderr}")

            # Parse the CSV output
            import csv
            from io import StringIO

            reader = csv.DictReader(StringIO(stdout))
            software_list = list(reader)

            # Clean up the data
            for software in software_list:
                # Convert InstallDate to a standard format if present
                if "InstallDate" in software and software["InstallDate"]:
                    try:
                        # Install date is in format YYYYMMDD
                        date_str = software["InstallDate"]
                        if len(date_str) == 8:
                            software["InstallDate"] = f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:8]}"
                    except Exception:
                        # Keep the original value if parsing fails
                        pass

            return software_list

        except Exception as e:
            raise ConnectionError(f"Error getting installed software on {self.target.name}: {e}")

    def _get_installed_software_linux(self) -> List[Dict[str, any]]:
        """Get a list of installed software on Linux.

        Returns:
            List of dictionaries containing software information
        """
        try:
            logger.debug(f"Getting installed software on {self.target.name} (Linux)")

            # Try to determine the package manager
            if self.file_exists("/usr/bin/dpkg"):
                # Debian-based (Ubuntu, Debian, etc.)
                exit_code, stdout, stderr = self.execute_command(
                    ["dpkg-query", "-W", "-f=${Package},${Version},${Status}\n"])

                if exit_code != 0:
                    raise ConnectionError(f"Error getting installed software: {stderr}")

                # Parse the output
                software_list = []
                for line in stdout.splitlines():
                    parts = line.strip().split(",")
                    if len(parts) >= 3 and "installed" in parts[2]:
                        software_list.append({
                            "Name": parts[0],
                            "Version": parts[1],
                            "Vendor": "Unknown",
                            "InstallDate": "Unknown",
                        })

                return software_list

            elif self.file_exists("/usr/bin/rpm"):
                # RPM-based (RHEL, CentOS, Fedora, etc.)
                exit_code, stdout, stderr = self.execute_command(
                    ["rpm", "-qa", "--queryformat", "%{NAME},%{VERSION},%{VENDOR},%{INSTALLTIME:date}\n"])

                if exit_code != 0:
                    raise ConnectionError(f"Error getting installed software: {stderr}")

                # Parse the output
                software_list = []
                for line in stdout.splitlines():
                    parts = line.strip().split(",")
                    if len(parts) >= 4:
                        software_list.append({
                            "Name": parts[0],
                            "Version": parts[1],
                            "Vendor": parts[2],
                            "InstallDate": parts[3],
                        })

                return software_list

            else:
                # Unsupported package manager
                logger.warning("Unsupported package manager on Linux")
                return []

        except Exception as e:
            raise ConnectionError(f"Error getting installed software on {self.target.name}: {e}")
