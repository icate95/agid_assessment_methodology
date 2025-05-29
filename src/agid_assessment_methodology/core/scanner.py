"""Modulo Scanner per la raccolta di informazioni di sicurezza."""

import platform
import logging
from typing import Dict, Any, Optional, List

# Importa utilities
from ..utils.logger import get_logger

logger = get_logger(__name__)


class Scanner:
    """Scanner per valutazioni di sicurezza su sistemi target."""

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        Inizializza un nuovo scanner.

        Args:
            target: Sistema target (hostname, IP, o percorso locale)
            config: Configurazione opzionale per lo scanner
        """
        self.target = target
        self.config = config or {}
        self.os_type = None
        self._is_local = self._check_if_local_target()

    def _check_if_local_target(self) -> bool:
        """
        Determina se il target è il sistema locale.

        Returns:
            True se il target è locale, False altrimenti
        """
        local_targets = {"localhost", "127.0.0.1", "::1", "."}
        return self.target in local_targets

    def detect_os(self) -> str:
        """
        Rileva il tipo di sistema operativo del target.

        Returns:
            String che rappresenta il tipo di OS (windows, linux, macos, unknown)
        """
        if self._is_local:
            # Per il sistema locale, usa platform
            sys_platform = platform.system().lower()
            if sys_platform == "windows":
                self.os_type = "windows"
            elif sys_platform == "linux":
                self.os_type = "linux"
            elif sys_platform == "darwin":
                self.os_type = "macos"
            else:
                self.os_type = "unknown"
        else:
            # Per sistemi remoti, per ora impostiamo come sconosciuto
            # In futuro implementeremo il rilevamento remoto
            self.os_type = "unknown"
            logger.warning(f"Remote OS detection not implemented for {self.target}")

        logger.info(f"Detected OS type: {self.os_type} for target: {self.target}")
        return self.os_type

    def get_system_info(self) -> Dict[str, Any]:
        """
        Raccoglie informazioni di base sul sistema target.

        Returns:
            Dizionario con informazioni del sistema
        """
        info = {
            "target": self.target,
            "is_local": self._is_local,
            "os_type": self.os_type or self.detect_os(),
            "scan_timestamp": None,  # Sarà impostato quando eseguiamo la scansione
        }

        if self._is_local:
            # Aggiungi informazioni dettagliate per il sistema locale
            try:
                info.update({
                    "hostname": platform.node(),
                    "platform": platform.platform(),
                    "architecture": platform.architecture(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version(),
                })
            except Exception as e:
                logger.error(f"Error collecting system info: {e}")

        return info

    def get_available_checks(self) -> List[str]:
        """
        Restituisce la lista dei controlli disponibili per questo target.

        Returns:
            Lista dei nomi dei controlli disponibili
        """
        # Importa il registro dei checks
        from ..checks import registry

        # Rileva OS se non già fatto
        if not self.os_type:
            self.detect_os()

        # Ottieni i checks compatibili con questo OS
        compatible_checks = registry.get_checks_for_os(self.os_type)
        return [check.id for check in compatible_checks]

    def run_basic_scan(self) -> Dict[str, Any]:
        """
        Esegue una scansione di base del sistema usando i checks registrati.

        Returns:
            Dizionario con i risultati della scansione
        """
        logger.info(f"Starting basic scan of target: {self.target}")

        # Importa il registro dei checks
        from ..checks import registry

        # Prepara il contesto per i checks
        context = {
            "target": self.target,
            "os_type": self.os_type or self.detect_os(),
            "is_local": self._is_local,
            "scanner_config": self.config
        }

        # Esegui tutti i checks disponibili per questo OS
        check_results = registry.execute_checks(context)

        # Converte i risultati in formato compatibile con Assessment
        results = {}
        for check_id, check_result in check_results.items():
            results[check_id] = check_result.to_dict()

        # Aggiungi timestamp e metadati
        from datetime import datetime
        results["scan_metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "scanner_version": "0.1.0",
            "checks_executed": len(check_results),
            "os_type": context["os_type"]
        }

        logger.info(f"Basic scan completed for target: {self.target}")
        return results

    # Aggiungere questo metodo alla classe Scanner in src/agid_assessment_methodology/core/scanner.py

    def scan(self, enabled_categories: Optional[List[str]] = None, specific_checks: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Esegue una scansione del sistema con filtri opzionali.

        Args:
            enabled_categories: Lista delle categorie di controlli da eseguire
            specific_checks: Lista dei controlli specifici da eseguire

        Returns:
            Dizionario con i risultati della scansione
        """
        logger.info(f"Starting scan of target: {self.target}")

        # Importa il registro dei checks
        from ..checks import registry

        # Prepara il contesto per i checks
        context = {
            "target": self.target,
            "os_type": self.os_type or self.detect_os(),
            "is_local": self._is_local,
            "scanner_config": self.config
        }

        # Applica filtri se specificati
        if enabled_categories or specific_checks:
            # Se sono specificati filtri, esegui solo i controlli specifici
            if specific_checks:
                # Esegui solo i controlli specifici
                check_results = registry.execute_checks(context, check_ids=specific_checks)
            else:
                # Esegui solo le categorie specificate
                check_results = registry.execute_checks(context, categories=enabled_categories)
        else:
            # Esegui tutti i checks disponibili
            check_results = registry.execute_checks(context)

        # Converte i risultati in formato compatibile con Assessment
        # E categorizza correttamente i risultati
        categorized_results = {
            'scan_metadata': check_results.get('scan_metadata', {}),

        }

        for check_id, check_result in check_results.items():
            result_dict = check_result.to_dict()

            # Ottieni la categoria dal check result
            category = result_dict.get('category', 'system')  # default 'system' invece di 'unknown'

            # Se la categoria non esiste ancora, creala
            if category not in categorized_results:
                categorized_results[category] = {}

            # Aggiungi il risultato alla categoria appropriata
            categorized_results[category][check_id] = result_dict

        # Aggiungi timestamp e metadati
        from datetime import datetime
        categorized_results["scan_metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "scanner_version": "0.1.0",
            "checks_executed": len(check_results),
            "os_type": context["os_type"],
            "enabled_categories": enabled_categories,
            "specific_checks": specific_checks
        }

        logger.info(f"Scan completed for target: {self.target}")
        return categorized_results

    def __str__(self) -> str:
        """Rappresentazione string del scanner."""
        return f"Scanner(target='{self.target}', os_type='{self.os_type}')"

    def __repr__(self) -> str:
        """Rappresentazione dettagliata del scanner."""
        return f"Scanner(target='{self.target}', config={self.config}, os_type='{self.os_type}')"