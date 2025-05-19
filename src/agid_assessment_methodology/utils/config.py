"""Gestione della configurazione per AGID Assessment Methodology."""

import os
import json
import logging
from typing import Dict, Any, Optional, Union
from pathlib import Path
import jsonschema
import platform

logger = logging.getLogger(__name__)

# Configurazione di default
DEFAULT_CONFIG = {
    "scan": {
        "timeout": 300,
        "parallel": True,
        "max_threads": 10,
        "retry_attempts": 2,
        "retry_delay": 5
    },
    "checks": {
        "enabled_categories": [
            "authentication",
            "system",
            "network",
            "malware",
            "backup",
            "logging",
            "encryption"
        ],
        "excluded_checks": [],
        "severity_threshold": "medium",  # low, medium, high, critical
        "custom_thresholds": {}
    },
    "reporting": {
        "include_details": True,
        "include_recommendations": True,
        "include_raw_data": False,
        "default_format": "json",
        "output_directory": "reports",
        "template_directory": "templates"
    },
    "credentials": {
        "windows": {
            "username": "",
            "password": "",
            "domain": "",
            "use_current_user": True
        },
        "linux": {
            "username": "",
            "use_key": True,
            "key_path": "",
            "password": "",
            "port": 22
        }
    },
    "logging": {
        "level": "INFO",
        "file_logging": True,
        "log_directory": "logs",
        "max_file_size": "10MB",
        "backup_count": 5,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    },
    "database": {
        "type": "sqlite",
        "sqlite_path": "agid_assessment.db",
        "postgresql": {
            "host": "localhost",
            "port": 5432,
            "database": "agid_assessment",
            "username": "",
            "password": ""
        }
    }
}

# Schema di validazione per la configurazione
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "scan": {
            "type": "object",
            "properties": {
                "timeout": {"type": "integer", "minimum": 30},
                "parallel": {"type": "boolean"},
                "max_threads": {"type": "integer", "minimum": 1, "maximum": 50},
                "retry_attempts": {"type": "integer", "minimum": 0},
                "retry_delay": {"type": "integer", "minimum": 1}
            }
        },
        "checks": {
            "type": "object",
            "properties": {
                "enabled_categories": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "excluded_checks": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"]
                }
            }
        },
        "reporting": {
            "type": "object",
            "properties": {
                "include_details": {"type": "boolean"},
                "include_recommendations": {"type": "boolean"},
                "include_raw_data": {"type": "boolean"},
                "default_format": {
                    "type": "string",
                    "enum": ["json", "csv", "html", "pdf"]
                }
            }
        },
        "logging": {
            "type": "object",
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
                },
                "file_logging": {"type": "boolean"}
            }
        }
    }
}


def load_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Carica la configurazione da un file.

    Args:
        config_path: Percorso al file di configurazione

    Returns:
        Dizionario con la configurazione
    """
    if config_path is None:
        # Cerca file di configurazione in posizioni standard
        config_path = find_config_file()

    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Valida la configurazione
            if validate_config(config):
                # Unisce con la configurazione di default
                merged_config = merge_configs(DEFAULT_CONFIG, config)
                logger.info(f"Configuration loaded from {config_path}")
                return merged_config
            else:
                logger.warning(f"Invalid configuration in {config_path}, using defaults")
                return DEFAULT_CONFIG.copy()

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file {config_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error loading config file {config_path}: {str(e)}")

    logger.info("Using default configuration")
    return DEFAULT_CONFIG.copy()


def save_config(config: Dict[str, Any], config_path: Union[str, Path]) -> bool:
    """
    Salva la configurazione in un file.

    Args:
        config: Configurazione da salvare
        config_path: Percorso al file di configurazione

    Returns:
        True se il salvataggio è riuscito, False altrimenti
    """
    try:
        # Valida la configurazione prima di salvarla
        if not validate_config(config):
            logger.error("Invalid configuration, not saving")
            return False

        # Assicura che la directory esista
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        logger.info(f"Configuration saved to {config_path}")
        return True

    except Exception as e:
        logger.error(f"Error saving config file {config_path}: {str(e)}")
        return False


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Valida la configurazione contro lo schema.

    Args:
        config: Configurazione da validare

    Returns:
        True se la configurazione è valida
    """
    try:
        jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)
        return True
    except jsonschema.exceptions.ValidationError as e:
        logger.error(f"Configuration validation error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during configuration validation: {str(e)}")
        return False


def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Unisce due configurazioni, con la seconda che sovrascrive la prima.

    Args:
        base_config: Configurazione di base
        override_config: Configurazione di override

    Returns:
        Configurazione unita
    """

    def _merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge ricorsivo di dizionari."""
        result = base.copy()

        for key, value in override.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                # Merge ricorsivo per i sotto-dizionari
                result[key] = _merge_dict(result[key], value)
            else:
                # Sovrascrivi il valore
                result[key] = value

        return result

    return _merge_dict(base_config, override_config)


def find_config_file() -> Optional[str]:
    """
    Cerca file di configurazione in posizioni standard.

    Returns:
        Percorso al file di configurazione se trovato, None altrimenti
    """
    # Possibili posizioni del file di configurazione
    config_locations = [
        # Directory corrente
        "agid_assessment.json",
        ".agid_assessment.json",
        # Directory home utente
        os.path.expanduser("~/.agid_assessment/config.json"),
        os.path.expanduser("~/.config/agid_assessment/config.json"),
        # Directory di sistema
        "/etc/agid_assessment/config.json",
        # Variabile d'ambiente
        os.environ.get("AGID_ASSESSMENT_CONFIG", "")
    ]

    for location in config_locations:
        if location and os.path.isfile(location):
            logger.debug(f"Found config file at {location}")
            return location

    return None


def get_config_value(config: Dict[str, Any], key_path: str, default: Any = None) -> Any:
    """
    Ottiene un valore dalla configurazione usando un percorso con punti.

    Args:
        config: Configurazione
        key_path: Percorso alla chiave (es. "scan.timeout")
        default: Valore di default se la chiave non esiste

    Returns:
        Valore della configurazione
    """
    try:
        keys = key_path.split('.')
        value = config

        for key in keys:
            value = value[key]

        return value
    except (KeyError, TypeError):
        return default


def set_config_value(config: Dict[str, Any], key_path: str, value: Any) -> None:
    """
    Imposta un valore nella configurazione usando un percorso con punti.

    Args:
        config: Configurazione
        key_path: Percorso alla chiave (es. "scan.timeout")
        value: Valore da impostare
    """
    keys = key_path.split('.')
    current = config

    # Naviga fino al penultimo livello
    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    # Imposta il valore finale
    current[keys[-1]] = value


def get_user_config_dir() -> Path:
    """
    Ottiene la directory di configurazione dell'utente.

    Returns:
        Percorso alla directory di configurazione
    """
    # Su Windows usa APPDATA, su Unix usa ~/.config
    if os.name == 'nt':
        config_dir = Path(os.environ.get('APPDATA', os.path.expanduser('~'))) / 'agid_assessment'
    else:
        config_dir = Path(os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))) / 'agid_assessment'

    return config_dir


def ensure_config_dir() -> Path:
    """
    Assicura che la directory di configurazione esista.

    Returns:
        Percorso alla directory di configurazione
    """
    config_dir = get_user_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir
# Aggiungere questa funzione al file src/agid_assessment_methodology/utils/config.py

def create_default_config() -> Dict[str, Any]:
    """
    Crea una configurazione di default.

    Returns:
        Dizionario con la configurazione di default
    """
    return {
        "logging": {
            "level": "INFO",
            "file_logging": True,
            "log_file": str(Path.home() / ".agid_assessment" / "logs" / "assessment.log"),
            "max_file_size": "10MB",
            "backup_count": 5,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "scan": {
            "timeout": 300,
            "parallel": True,
            "max_workers": 4,
            "retry_attempts": 3,
            "retry_delay": 1.0
        },
        "checks": {
            "enabled_categories": ["system", "authentication", "network", "logging"],
            "excluded_checks": [],
            "custom_checks_path": None
        },
        "reporting": {
            "include_raw_data": True,
            "include_system_info": True,
            "default_format": "html",
            "output_directory": str(Path.home() / ".agid_assessment" / "reports")
        },
        "credentials": {
            "store_encrypted": True,
            "use_system_credentials": True
        }
    }


def get_user_config_dir() -> Path:
    """
    Ottiene la directory di configurazione dell'utente.

    Returns:
        Path della directory di configurazione
    """
    if platform.system() == "Windows":
        config_dir = Path.home() / "AppData" / "Local" / "agid_assessment"
    elif platform.system() == "Darwin":  # macOS
        config_dir = Path.home() / "Library" / "Application Support" / "agid_assessment"
    else:  # Linux e altri Unix
        config_dir = Path.home() / ".config" / "agid_assessment"

    # Crea la directory se non esiste
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir
def ensure_config_dir() -> Path:
    """
    Assicura che la directory di configurazione esista.

    Returns:
        Percorso alla directory di configurazione
    """
    config_dir = get_user_config_dir()
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir




if __name__ == "__main__":
    # Esempio di utilizzo
    config = load_config()
    print("Default config loaded")
    print(f"Scan timeout: {get_config_value(config, 'scan.timeout')}")

    # Salva configurazione in directory utente
    user_config_dir = ensure_config_dir()
    save_config(config, user_config_dir / "config.json")