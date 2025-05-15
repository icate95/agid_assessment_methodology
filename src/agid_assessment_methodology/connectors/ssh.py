"""SSH connector for remote system assessment.

This module provides functionality for connecting to remote systems via SSH
to perform security checks.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import paramiko

from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.engine import Target
from agid_assessment_methodology.utils.exceptions import ConnectionError

logger = logging.getLogger(__name__)


class SSHConnector:
    """SSH connector for remote system assessment."""

    def __init__(self, target: Target):
        """Initialize the SSH connector.

        Args:
            target: Target system to connect to
        """
        self.target = target
        self.client = None
        self.sftp = None
        self._validate_target()
        logger.debug(f"Initialized SSH connector for target: {self.target.name}")

    def _validate_target(self) -> None:
        """Validate the target configuration."""
        if self.target.type != "linux":
            raise ConnectionError(f"SSHConnector requires a 'linux' target type, got '{self.target.type}'")

        if not self.target.host:
            raise ConnectionError("SSHConnector requires a host")

        if not (self.target.username and (self.target.password or self.target.key_file)):
            raise ConnectionError("SSHConnector requires username and either password or key_file")

    def connect(self) -> None:
        """Connect to the target system."""
        if self.client:
            logger.debug(f"Already connected to {self.target.name}")
            return

        try:
            # Create a new SSH client
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the target
            connect_kwargs = {
                "hostname": self.target.host,
                "username": self.target.username,
                "port": self.target.port or 22,
                "timeout": settings.ssh_timeout,
            }

            if self.target.key_file:
                connect_kwargs["key_filename"] = str(self.target.key_file)
            else:
                connect_kwargs["password"] = self.target.password

            logger.debug(f"Connecting to {self.target.name} ({self.target.host})")
            self.client.connect(**connect_kwargs)

            # Create SFTP client
            self.sftp = self.client.open_sftp()

            logger.info(f"Successfully connected to {self.target.name} ({self.target.host})")

        except Exception as e:
            self.disconnect()
            raise ConnectionError(f"Error connecting to {self.target.name} ({self.target.host}): {e}")

    def disconnect(self) -> None:
        """Disconnect from the target system."""
        if self.sftp:
            try:
                self.sftp.close()
            except Exception as e:
                logger.warning(f"Error closing SFTP connection: {e}")
            self.sftp = None

        if self.client:
            try:
                self.client.close()
            except Exception as e:
                logger.warning(f"Error closing SSH connection: {e}")
            self.client = None

            logger.info(f"Disconnected from {self.target.name}")

    def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        get_pty: bool = False,
    ) -> Tuple[int, str, str]:
        """Execute a command on the target system.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds, or None for default
            get_pty: Whether to allocate a pseudo-terminal

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self.client:
            self.connect()

        try:
            logger.debug(f"Executing command on {self.target.name}: {command}")

            # Execute the command
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout or settings.ssh_timeout,
                get_pty=get_pty
            )

            # Read command output
            stdout_str = stdout.read().decode("utf-8", errors="replace")
            stderr_str = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()

            logger.debug(f"Command exit code: {exit_code}")
            return exit_code, stdout_str, stderr_str

        except Exception as e:
            raise ConnectionError(f"Error executing command on {self.target.name}: {e}")

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the target system.

        Args:
            path: Path to the file

        Returns:
            True if the file exists, False otherwise
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Checking if file exists on {self.target.name}: {path}")
            self.sftp.stat(path)
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.warning(f"Error checking if file exists on {self.target.name}: {e}")
            return False

    def read_file(self, path: str) -> str:
        """Read a file from the target system.

        Args:
            path: Path to the file

        Returns:
            File contents
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Reading file from {self.target.name}: {path}")

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name

            # Download the file
            self.sftp.get(path, temp_path)

            # Read the file
            with open(temp_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Clean up
            os.remove(temp_path)

            return content

        except Exception as e:
            # Clean up
            if "temp_path" in locals():
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

            raise ConnectionError(f"Error reading file from {self.target.name}: {e}")

    def read_file_binary(self, path: str) -> bytes:
        """Read a binary file from the target system.

        Args:
            path: Path to the file

        Returns:
            File contents as bytes
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Reading binary file from {self.target.name}: {path}")

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name

            # Download the file
            self.sftp.get(path, temp_path)

            # Read the file
            with open(temp_path, "rb") as f:
                content = f.read()

            # Clean up
            os.remove(temp_path)

            return content

        except Exception as e:
            # Clean up
            if "temp_path" in locals():
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

            raise ConnectionError(f"Error reading binary file from {self.target.name}: {e}")

    def write_file(self, path: str, content: str) -> None:
        """Write a file to the target system.

        Args:
            path: Path to the file
            content: File contents
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Writing file to {self.target.name}: {path}")

            with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name

            # Upload the file
            self.sftp.put(temp_path, path)

            # Clean up
            os.remove(temp_path)

        except Exception as e:
            # Clean up
            if "temp_path" in locals():
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

            raise ConnectionError(f"Error writing file to {self.target.name}: {e}")

    def write_file_binary(self, path: str, content: bytes) -> None:
        """Write a binary file to the target system.

        Args:
            path: Path to the file
            content: File contents as bytes
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Writing binary file to {self.target.name}: {path}")

            with tempfile.NamedTemporaryFile(delete=False, mode="wb") as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name

            # Upload the file
            self.sftp.put(temp_path, path)

            # Clean up
            os.remove(temp_path)

        except Exception as e:
            # Clean up
            if "temp_path" in locals():
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

            raise ConnectionError(f"Error writing binary file to {self.target.name}: {e}")

    def list_directory(self, path: str) -> List[str]:
        """List files in a directory on the target system.

        Args:
            path: Path to the directory

        Returns:
            List of filenames
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Listing directory on {self.target.name}: {path}")
            return self.sftp.listdir(path)

        except Exception as e:
            raise ConnectionError(f"Error listing directory on {self.target.name}: {e}")

    def get_file_stats(self, path: str) -> Dict[str, any]:
        """Get file statistics on the target system.

        Args:
            path: Path to the file

        Returns:
            Dictionary of file statistics
        """
        if not self.sftp:
            self.connect()

        try:
            logger.debug(f"Getting file stats on {self.target.name}: {path}")
            stats = self.sftp.stat(path)

            return {
                "size": stats.st_size,
                "uid": stats.st_uid,
                "gid": stats.st_gid,
                "mode": stats.st_mode,
                "atime": stats.st_atime,
                "mtime": stats.st_mtime,
            }

        except Exception as e:
            raise ConnectionError(f"Error getting file stats on {self.target.name}: {e}")

    def __enter__(self) -> SSHConnector:
        """Enter context manager."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager."""
        self.disconnect()
