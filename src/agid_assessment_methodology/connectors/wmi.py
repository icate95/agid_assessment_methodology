"""WMI connector for Windows system assessment.

This module provides functionality for connecting to Windows systems via WMI
to perform security checks.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import wmi

from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.engine import Target
from agid_assessment_methodology.utils.exceptions import ConnectionError

logger = logging.getLogger(__name__)


class WMIConnector:
    """WMI connector for Windows system assessment."""

    def __init__(self, target: Target):
        """Initialize the WMI connector.

        Args:
            target: Target system to connect to
        """
        self.target = target
        self.connection = None
        self._validate_target()
        logger.debug(f"Initialized WMI connector for target: {self.target.name}")

    def _validate_target(self) -> None:
        """Validate the target configuration."""
        if self.target.type != "windows":
            raise ConnectionError(f"WMIConnector requires a 'windows' target type, got '{self.target.type}'")

        if not self.target.host:
            raise ConnectionError("WMIConnector requires a host")

        if not (self.target.username and self.target.password):
            raise ConnectionError("WMIConnector requires username and password")

    def connect(self) -> None:
        """Connect to the target system."""
        if self.connection:
            logger.debug(f"Already connected to {self.target.name}")
            return

        try:
            # Create a new WMI connection
            auth_info = {}

            # Add username and password
            auth_info["user"] = self.target.username
            auth_info["password"] = self.target.password

            # Add domain if provided
            if self.target.domain:
                auth_info["domain"] = self.target.domain

            logger.debug(f"Connecting to {self.target.name} ({self.target.host})")

            # Create the connection
            self.connection = wmi.WMI(
                computer=self.target.host,
                **auth_info
            )

            logger.info(f"Successfully connected to {self.target.name} ({self.target.host})")

        except Exception as e:
            self.disconnect()
            raise ConnectionError(f"Error connecting to {self.target.name} ({self.target.host}): {e}")

    def disconnect(self) -> None:
        """Disconnect from the target system."""
        # WMI does not have an explicit disconnect method
        # Just clear the connection reference
        self.connection = None
        logger.info(f"Disconnected from {self.target.name}")

    def execute_wql(self, query: str) -> List[Any]:
        """Execute a WQL query on the target system.

        Args:
            query: WQL query to execute

        Returns:
            List of query results
        """
        if not self.connection:
            self.connect()

        try:
            logger.debug(f"Executing WQL query on {self.target.name}: {query}")

            # Execute the query
            results = self.connection.query(query)

            return list(results)

        except Exception as e:
            raise ConnectionError(f"Error executing WQL query on {self.target.name}: {e}")

    def execute_powershell(self, script: str) -> Tuple[int, str, str]:
        """Execute a PowerShell script on the target system.

        Args:
            script: PowerShell script to execute

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self.connection:
            self.connect()

        try:
            logger.debug(f"Executing PowerShell script on {self.target.name}")

            # Create a temporary file for the script
            with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w") as f:
                f.write(script)
                script_path = f.name

            # Build the command to execute the script
            # Escape double quotes in the path
            escaped_path = script_path.replace("\\", "\\\\").replace('"', '\\"')
            command = f'powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "{escaped_path}"'

            # Create a process via WMI
            process = self.connection.Win32_Process.Create(CommandLine=command)

            # Check if the process was created successfully
            if process[0] != 0:
                raise ConnectionError(f"Error creating process: {process[1]}")

            # Get the process ID
            pid = process[1]

            # Wait for the process to complete
            process_obj = None
            for p in self.connection.Win32_Process(ProcessId=pid):
                process_obj = p
                break

            if not process_obj:
                raise ConnectionError(f"Process with ID {pid} not found")

            # Wait for the process to complete
            exit_code = None
            while exit_code is None:
                # Refresh the process object
                process_obj = None
                for p in self.connection.Win32_Process(ProcessId=pid):
                    process_obj = p
                    break

                if not process_obj:
                    # Process has terminated
                    exit_code = 0
                    break

            # Get the output and error (if any)
            # This is a simplification - in a real implementation,
            # you would need to redirect stdout and stderr to files
            # and read those files after the process completes
            stdout = ""
            stderr = ""

            # Clean up
            os.remove(script_path)

            return exit_code, stdout, stderr

        except Exception as e:
            # Clean up
            if "script_path" in locals():
                try:
                    os.remove(script_path)
                except Exception:
                    pass

            raise ConnectionError(f"Error executing PowerShell script on {self.target.name}: {e}")

    def get_registry_value(
        self,
        hive: str,
        key: str,
        value_name: Optional[str] = None
    ) -> Any:
        """Get a registry value from the target system.

        Args:
            hive: Registry hive (e.g., "HKLM", "HKCU")
            key: Registry key path
            value_name: Name of the value to get, or None for the default value

        Returns:
            Registry value
        """
        if not self.connection:
            self.connect()

        try:
            logger.debug(f"Getting registry value on {self.target.name}: {hive}\\{key}\\{value_name or '(Default)'}")

            # Map the hive name to its WMI constant
            if hive.upper() == "HKLM":
                hive_id = 0x80000002  # HKEY_LOCAL_MACHINE
            elif hive.upper() == "HKCU":
                hive_id = 0x80000001  # HKEY_CURRENT_USER
            elif hive.upper() == "HKCR":
                hive_id = 0x80000000  # HKEY_CLASSES_ROOT
            elif hive.upper() == "HKU":
                hive_id = 0x80000003  # HKEY_USERS
            elif hive.upper() == "HKCC":
                hive_id = 0x80000005  # HKEY_CURRENT_CONFIG
            else:
                raise ValueError(f"Unsupported registry hive: {hive}")

            # Get the registry provider
            reg_provider = self.connection.StdRegProv

            # Get the registry value
            if value_name is None:
                # Get the default value
                result = reg_provider.GetStringValue(hDefKey=hive_id, sSubKeyName=key, sValueName="")
            else:
                # Try to get the value as different types
                # Try string first
                result = reg_provider.GetStringValue(hDefKey=hive_id, sSubKeyName=key, sValueName=value_name)

                if result[0] != 0 or result[1] is None:
                    # Try DWORD
                    result = reg_provider.GetDWORDValue(hDefKey=hive_id, sSubKeyName=key, sValueName=value_name)

                if result[0] != 0 or result[1] is None:
                    # Try QWORD
                    result = reg_provider.GetQWORDValue(hDefKey=hive_id, sSubKeyName=key, sValueName=value_name)

                if result[0] != 0 or result[1] is None:
                    # Try binary
                    result = reg_provider.GetBinaryValue(hDefKey=hive_id, sSubKeyName=key, sValueName=value_name)

                if result[0] != 0 or result[1] is None:
                    # Try multi-string
                    result = reg_provider.GetMultiStringValue(hDefKey=hive_id, sSubKeyName=key, sValueName=value_name)

            if result[0] != 0:
                # Error
                return None

            return result[1]

        except Exception as e:
            raise ConnectionError(f"Error getting registry value on {self.target.name}: {e}")

    def get_service_status(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get the status of a service on the target system.

        Args:
            service_name: Name of the service

        Returns:
            Dictionary of service status information, or None if the service does not exist
        """
        if not self.connection:
            self.connect()

        try:
            logger.debug(f"Getting service status on {self.target.name}: {service_name}")

            # Query the service
            services = self.connection.Win32_Service(Name=service_name)

            # Check if the service exists
            if not services:
                return None

            # Get the first (and only) service
            service = services[0]

            # Return service information
            return {
                "name": service.Name,
                "display_name": service.DisplayName,
                "state": service.State,
                "start_mode": service.StartMode,
                "path": service.PathName,
                "account": service.StartName,
                "can_pause_and_continue": service.AcceptPause and service.AcceptStop,
                "description": service.Description,
            }

        except Exception as e:
            raise ConnectionError(f"Error getting service status on {self.target.name}: {e}")

    def get_process_list(self) -> List[Dict[str, Any]]:
        """Get a list of running processes on the target system.

        Returns:
            List of dictionaries containing process information
        """
        if not self.connection:
            self.connect()

        try:
            logger.debug(f"Getting process list on {self.target.name}")

            # Query all processes
            processes = self.connection.Win32_Process()

            # Build the result list
            result = []
            for process in processes:
                # Get the process owner
                owner = process.GetOwner()
                owner_name = f"{owner[1]}\\{owner[0]}" if owner[0] is not None else None

                # Add process information to the result
                result.append({
                    "id": process.ProcessId,
                    "name": process.Name,
                    "path": process.ExecutablePath,
                    "command_line": process.CommandLine,
                    "owner": owner_name,
                    "creation_date": process.CreationDate,
                    "working_set_size": process.WorkingSetSize,
                    "priority": process.Priority,
                })

            return result

        except Exception as e:
            raise ConnectionError(f"Error getting process list on {self.target.name}: {e}")

    def __enter__(self) -> WMIConnector:
        """Enter context manager."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        self.disconnect()
