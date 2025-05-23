"""
Utility helper functions for the AGID Assessment Methodology.

This module provides common utility functions used throughout the assessment framework.
"""

import os
import platform
import subprocess
import logging
import threading
import signal
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)


def run_command(
    command: Union[str, List[str]],
    timeout: Optional[int] = 30,
    shell: bool = False,
    capture_output: bool = True,
    text: bool = True,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Run a system command with timeout and error handling.
    
    Args:
        command: Command to run (string or list of arguments)
        timeout: Command timeout in seconds
        shell: Whether to run in shell mode
        capture_output: Whether to capture stdout/stderr
        text: Whether to return text output (vs bytes)
        env: Environment variables for the command
        cwd: Working directory for the command
        
    Returns:
        Dictionary with command results or None on error
    """
    try:
        # Convert string command to list if needed
        if isinstance(command, str) and not shell:
            command = command.split()
        
        # Set up process arguments
        process_args = {
            'timeout': timeout,
            'shell': shell,
            'text': text,
            'env': env,
            'cwd': cwd
        }
        
        if capture_output:
            process_args.update({
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE
            })
        
        # Run the command
        result = subprocess.run(command, **process_args)
        
        return {
            'returncode': result.returncode,
            'stdout': result.stdout if capture_output else '',
            'stderr': result.stderr if capture_output else '',
            'command': command,
            'success': result.returncode == 0
        }
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out after {timeout} seconds: {command}")
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': f'Command timed out after {timeout} seconds',
            'command': command,
            'success': False,
            'timeout': True
        }
        
    except subprocess.CalledProcessError as e:
        logger.warning(f"Command failed with return code {e.returncode}: {command}")
        return {
            'returncode': e.returncode,
            'stdout': e.stdout if capture_output else '',
            'stderr': e.stderr if capture_output else '',
            'command': command,
            'success': False
        }
        
    except Exception as e:
        logger.error(f"Error running command {command}: {str(e)}")
        return {
            'returncode': -2,
            'stdout': '',
            'stderr': str(e),
            'command': command,
            'success': False,
            'error': str(e)
        }


def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system().lower() == 'windows'


def is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system().lower() == 'linux'


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system().lower() == 'darwin'


def get_os_type() -> str:
    """
    Get standardized OS type string.
    
    Returns:
        OS type: 'windows', 'linux', 'macos', or 'unknown'
    """
    system = platform.system().lower()
    if system == 'windows':
        return 'windows'
    elif system == 'linux':
        return 'linux'
    elif system == 'darwin':
        return 'macos'
    else:
        return 'unknown'


def safe_get_nested_dict(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """
    Safely get nested dictionary value.
    
    Args:
        data: Dictionary to search
        keys: List of keys to traverse
        default: Default value if key path not found
        
    Returns:
        Value at key path or default
    """
    try:
        current = data
        for key in keys:
            current = current[key]
        return current
    except (KeyError, TypeError):
        return default


def ensure_directory(path: Union[str, Path]) -> bool:
    """
    Ensure directory exists, create if needed.
    
    Args:
        path: Directory path to ensure
        
    Returns:
        True if directory exists or was created successfully
    """
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Failed to create directory {path}: {str(e)}")
        return False


def file_exists_and_readable(path: Union[str, Path]) -> bool:
    """
    Check if file exists and is readable.
    
    Args:
        path: File path to check
        
    Returns:
        True if file exists and is readable
    """
    try:
        file_path = Path(path)
        return file_path.exists() and file_path.is_file() and os.access(str(file_path), os.R_OK)
    except Exception:
        return False


def get_file_size(path: Union[str, Path]) -> Optional[int]:
    """
    Get file size in bytes.
    
    Args:
        path: File path
        
    Returns:
        File size in bytes or None if error
    """
    try:
        return Path(path).stat().st_size
    except Exception:
        return None


def get_file_modification_time(path: Union[str, Path]) -> Optional[float]:
    """
    Get file modification time as timestamp.
    
    Args:
        path: File path
        
    Returns:
        Modification time timestamp or None if error
    """
    try:
        return Path(path).stat().st_mtime
    except Exception:
        return None


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing/replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    import re
    
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove trailing dots and spaces
    sanitized = sanitized.rstrip('. ')
    
    # Ensure not empty
    if not sanitized:
        sanitized = 'unnamed_file'
    
    return sanitized


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes as human readable string.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    if bytes_value == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while bytes_value >= 1024 and i < len(size_names) - 1:
        bytes_value /= 1024.0
        i += 1
    
    return f"{bytes_value:.1f} {size_names[i]}"


def parse_port_range(port_range: str) -> List[int]:
    """
    Parse port range string into list of port numbers.
    
    Args:
        port_range: Port range string (e.g., "80,443,8000-8080")
        
    Returns:
        List of port numbers
    """
    ports = []
    
    try:
        parts = port_range.split(',')
        
        for part in parts:
            part = part.strip()
            
            if '-' in part:
                # Range of ports
                start, end = part.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if start_port <= end_port and start_port > 0 and end_port <= 65535:
                    ports.extend(range(start_port, end_port + 1))
            else:
                # Single port
                port = int(part)
                if 0 < port <= 65535:
                    ports.append(port)
                    
    except ValueError as e:
        logger.warning(f"Error parsing port range '{port_range}': {str(e)}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def validate_hostname(hostname: str) -> bool:
    """
    Validate hostname format.
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        True if hostname is valid
    """
    import re
    
    if not hostname or len(hostname) > 253:
        return False
    
    # Check for valid hostname pattern
    hostname_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    )
    
    return hostname_pattern.match(hostname) is not None


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format (IPv4 or IPv6).
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if IP address is valid
    """
    import ipaddress
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_system_info() -> Dict[str, Any]:
    """
    Get basic system information.
    
    Returns:
        Dictionary with system information
    """
    info = {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'hostname': platform.node()
    }
    
    # Add OS-specific information
    if is_windows():
        info['windows_edition'] = platform.win32_edition() if hasattr(platform, 'win32_edition') else 'Unknown'
        info['windows_version'] = platform.win32_ver()
    elif is_linux():
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_release[key] = value.strip('"')
                info['linux_distribution'] = os_release
        except Exception:
            info['linux_distribution'] = {}
    elif is_macos():
        info['macos_version'] = platform.mac_ver()
    
    return info


def kill_process_tree(pid: int, sig: int = signal.SIGTERM) -> bool:
    """
    Kill a process and all its children.
    
    Args:
        pid: Process ID to kill
        sig: Signal to send
        
    Returns:
        True if successful
    """
    try:
        import psutil
        
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        
        # Kill children first
        for child in children:
            try:
                child.send_signal(sig)
            except psutil.NoSuchProcess:
                pass
        
        # Kill parent
        parent.send_signal(sig)
        
        # Wait for processes to terminate
        gone, alive = psutil.wait_procs(children + [parent], timeout=3)
        
        # Force kill if still alive
        for proc in alive:
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
        
        return True
        
    except ImportError:
        # Fallback without psutil
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return True  # Process already dead
        except Exception:
            return False
    except Exception as e:
        logger.error(f"Error killing process tree {pid}: {str(e)}")
        return False


def get_available_memory() -> Optional[int]:
    """
    Get available system memory in bytes.
    
    Returns:
        Available memory in bytes or None if unable to determine
    """
    try:
        import psutil
        return psutil.virtual_memory().available
    except ImportError:
        # Fallback methods for different OS
        if is_linux():
            try:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            # Value is in KB
                            return int(line.split()[1]) * 1024
            except Exception:
                pass
        elif is_windows():
            try:
                result = run_command(['wmic', 'OS', 'get', 'FreePhysicalMemory', '/value'], timeout=10)
                if result and result.get('success'):
                    for line in result['stdout'].split('\n'):
                        if 'FreePhysicalMemory=' in line:
                            # Value is in KB
                            return int(line.split('=')[1]) * 1024
            except Exception:
                pass
    
    return None


def get_disk_usage(path: Union[str, Path]) -> Optional[Dict[str, int]]:
    """
    Get disk usage statistics for a path.
    
    Args:
        path: Path to check disk usage for
        
    Returns:
        Dictionary with total, used, and free space in bytes
    """
    try:
        import shutil
        
        total, used, free = shutil.disk_usage(str(path))
        
        return {
            'total': total,
            'used': used,
            'free': free,
            'used_percent': round((used / total) * 100, 2) if total > 0 else 0
        }
        
    except Exception as e:
        logger.warning(f"Could not get disk usage for {path}: {str(e)}")
        return None


def retry_on_exception(
    func,
    max_retries: int = 3,
    delay: float = 1.0,
    exceptions: tuple = (Exception,)
):
    """
    Decorator to retry function on specified exceptions.
    
    Args:
        func: Function to wrap
        max_retries: Maximum number of retries
        delay: Delay between retries in seconds
        exceptions: Tuple of exceptions to catch and retry on
        
    Returns:
        Decorated function
    """
    import time
    from functools import wraps
    
    @wraps(func)
    def wrapper(*args, **kwargs):
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except exceptions as e:
                last_exception = e
                if attempt < max_retries:
                    logger.debug(f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}")
                    time.sleep(delay * (2 ** attempt))  # Exponential backoff
                else:
                    logger.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
        
        raise last_exception
    
    return wrapper


def chunks(lst: List[Any], chunk_size: int):
    """
    Yield successive chunks from list.
    
    Args:
        lst: List to chunk
        chunk_size: Size of each chunk
        
    Yields:
        List chunks
    """
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Flatten nested dictionary.
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator for nested keys
        
    Returns:
        Flattened dictionary
    """
    items = []
    
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    
    return dict(items)


def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Get network interface information.
    
    Returns:
        List of network interface dictionaries
    """
    interfaces = []
    
    try:
        if is_windows():
            result = run_command(['ipconfig', '/all'], timeout=15)
            if result and result.get('success'):
                # Parse ipconfig output (simplified)
                current_interface = {}
                for line in result['stdout'].split('\n'):
                    line = line.strip()
                    if 'adapter' in line.lower() and ':' in line:
                        if current_interface:
                            interfaces.append(current_interface)
                        current_interface = {'name': line.split(':')[0].strip()}
                    elif 'IPv4 Address' in line or 'IP Address' in line:
                        ip = line.split(':')[-1].strip().rstrip('(Preferred)')
                        current_interface['ipv4'] = ip
                    elif 'Physical Address' in line:
                        mac = line.split(':')[-1].strip()
                        current_interface['mac'] = mac
                
                if current_interface:
                    interfaces.append(current_interface)
        else:
            # Linux/macOS
            result = run_command(['ip', 'addr', 'show'] if is_linux() else ['ifconfig'], timeout=15)
            if result and result.get('success'):
                # Parse output (simplified)
                current_interface = {}
                for line in result['stdout'].split('\n'):
                    line = line.strip()
                    if ':' in line and not line.startswith(' '):
                        if current_interface:
                            interfaces.append(current_interface)
                        interface_name = line.split(':')[1].strip() if is_linux() else line.split(':')[0]
                        current_interface = {'name': interface_name}
                    elif 'inet ' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'inet' and i + 1 < len(parts):
                                ip = parts[i + 1].split('/')[0]  # Remove CIDR notation
                                current_interface['ipv4'] = ip
                                break
                
                if current_interface:
                    interfaces.append(current_interface)
                    
    except Exception as e:
        logger.warning(f"Could not get network interfaces: {str(e)}")
    
    return interfaces


def is_port_in_use(port: int, host: str = 'localhost') -> bool:
    """
    Check if a port is in use.
    
    Args:
        port: Port number to check
        host: Host to check (default: localhost)
        
    Returns:
        True if port is in use
    """
    import socket
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception:
        return False