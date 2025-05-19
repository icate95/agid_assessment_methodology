"""Sistema di logging per AGID Assessment Methodology."""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Dict, Any, Union
from datetime import datetime


def setup_logger(
        level: Union[str, int] = logging.INFO,
        log_file: Optional[str] = None,
        log_dir: Optional[str] = None,
        format_string: Optional[str] = None,
        max_file_size: str = "10MB",
        backup_count: int = 5,
        console_output: bool = True
) -> logging.Logger:
    """
    Configura il sistema di logging.

    Args:
        level: Livello di logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Nome del file di log (opzionale)
        log_dir: Directory per i file di log
        format_string: Formato personalizzato per i log
        max_file_size: Dimensione massima del file di log
        backup_count: Numero di file di backup da mantenere
        console_output: Se mostrare l'output anche su console

    Returns:
        Logger configurato
    """
    # Ottiene il logger root per il package
    logger = logging.getLogger("agid_assessment_methodology")

    # Evita di aggiungere handler multipli
    if logger.handlers:
        return logger

    # Converte il livello se è una stringa
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    logger.setLevel(level)

    # Formato di default
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    formatter = logging.Formatter(format_string)

    # Handler per la console
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Handler per il file
    if log_file or log_dir:
        if log_dir:
            # Assicura che la directory esista
            Path(log_dir).mkdir(parents=True, exist_ok=True)

            if not log_file:
                # Genera nome file di default con timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                log_file = f"agid_assessment_{timestamp}.log"

            log_path = Path(log_dir) / log_file
        else:
            log_path = Path(log_file)

        # Converte la dimensione massima del file
        max_bytes = _parse_file_size(max_file_size)

        # Handler con rotazione automatica
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Ottiene un logger per un modulo specifico.

    Args:
        name: Nome del modulo

    Returns:
        Logger per il modulo
    """
    # Se il nome non inizia con il package name, lo aggiunge
    if not name.startswith("agid_assessment_methodology"):
        name = f"agid_assessment_methodology.{name}"

    return logging.getLogger(name)


def setup_logger_from_config(config: Dict[str, Any]) -> logging.Logger:
    """
    Configura il logger dalla configurazione.

    Args:
        config: Configurazione dell'applicazione

    Returns:
        Logger configurato
    """
    logging_config = config.get("logging", {})

    level = logging_config.get("level", "INFO")
    file_logging = logging_config.get("file_logging", True)
    log_dir = logging_config.get("log_directory", "logs")
    max_file_size = logging_config.get("max_file_size", "10MB")
    backup_count = logging_config.get("backup_count", 5)
    format_string = logging_config.get("format")

    # Configura il logging sui file solo se abilitato
    log_file = None
    if file_logging:
        log_file = "agid_assessment.log"

    return setup_logger(
        level=level,
        log_file=log_file,
        log_dir=log_dir if file_logging else None,
        format_string=format_string,
        max_file_size=max_file_size,
        backup_count=backup_count
    )


def _parse_file_size(size_string: str) -> int:
    """
    Converte una stringa di dimensione file in bytes.

    Args:
        size_string: Stringa come "10MB", "1GB", etc.

    Returns:
        Dimensione in bytes
    """
    size_string = size_string.upper().strip()

    # Dizionario delle unità
    units = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4
    }

    # Estrae numero e unità
    for unit, multiplier in units.items():
        if size_string.endswith(unit):
            try:
                number = float(size_string[:-len(unit)])
                return int(number * multiplier)
            except ValueError:
                pass

    # Se non riesce a parsare, assume bytes
    try:
        return int(size_string)
    except ValueError:
        # Default: 10MB
        return 10 * 1024 * 1024


class ContextFilter(logging.Filter):
    """Filtro per aggiungere contesto ai log."""

    def __init__(self, context: Dict[str, Any]):
        super().__init__()
        self.context = context

    def filter(self, record):
        """Aggiunge il contesto al record di log."""
        for key, value in self.context.items():
            setattr(record, key, value)
        return True


class ColoredFormatter(logging.Formatter):
    """Formatter con colori per output console."""

    # Codici colori ANSI
    COLORS = {
        'DEBUG': '\033[36m',  # Ciano
        'INFO': '\033[32m',  # Verde
        'WARNING': '\033[33m',  # Giallo
        'ERROR': '\033[31m',  # Rosso
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'  # Reset
    }

    def format(self, record):
        """Formatta il record con colori."""
        # Salva il formato originale
        original_format = self._style._fmt

        # Aggiunge colore al livello
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        colored_format = original_format.replace(
            '%(levelname)s',
            f'{color}%(levelname)s{self.COLORS["RESET"]}'
        )

        # Applica il formato colorato
        self._style._fmt = colored_format
        result = super().format(record)

        # Ripristina il formato originale
        self._style._fmt = original_format

        return result


def setup_colored_logger(
        level: Union[str, int] = logging.INFO,
        log_file: Optional[str] = None
) -> logging.Logger:
    """
    Configura un logger con output colorato per la console.

    Args:
        level: Livello di logging
        log_file: File di log opzionale

    Returns:
        Logger configurato con output colorato
    """
    logger = logging.getLogger("agid_assessment_methodology")

    # Evita handler duplicati
    if logger.handlers:
        return logger

    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    logger.setLevel(level)

    # Handler console con colori
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    colored_formatter = ColoredFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(colored_formatter)
    logger.addHandler(console_handler)

    # Handler file senza colori
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)

        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def log_function_call(logger: logging.Logger):
    """
    Decoratore per loggare chiamate a funzioni.

    Args:
        logger: Logger da utilizzare
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
            try:
                result = func(*args, **kwargs)
                logger.debug(f"{func.__name__} returned {result}")
                return result
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {str(e)}")
                raise

        return wrapper

    return decorator


def create_scan_logger(scan_id: str, log_dir: str = "logs") -> logging.Logger:
    """
    Crea un logger specifico per una scansione.

    Args:
        scan_id: ID univoco della scansione
        log_dir: Directory per i log

    Returns:
        Logger specifico per la scansione
    """
    logger_name = f"agid_assessment_methodology.scan.{scan_id}"
    logger = logging.getLogger(logger_name)

    # Se già configurato, restituisce il logger esistente
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # File di log specifico per questa scansione
    log_file = Path(log_dir) / f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    # Assicura che la directory esista
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Handler per il file
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - [%(levelname)s] - %(message)s"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger