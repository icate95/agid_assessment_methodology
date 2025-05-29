"""Registry per la gestione dei controlli di sicurezza."""

import logging
from typing import Dict, List, Optional, Type
from .base import BaseCheck, CheckResult
from collections import defaultdict

logger = logging.getLogger(__name__)


class CheckRegistry:
    """Registro centralizzato per i controlli di sicurezza."""

    def __init__(self):
        """Inizializza il registro."""
        self._checks: Dict[str, BaseCheck] = {}
        self._checks_by_category: Dict[str, List[BaseCheck]] = defaultdict(list)
        self._check_classes: Dict[str, Type[BaseCheck]] = {}

        # Log all'inizializzazione
        logger.debug("CheckRegistry initialized")

    def register(self, check: BaseCheck) -> None:
        """
        Registra un controllo.

        Args:
            check: Istanza del controllo da registrare
        """
        try:
            # if check.id in self._checks:
            #     logger.warning(f"Check {check.id} already registered, overwriting")

            # Assicurati che l'ID sia univoco
            if not check.id:
                check.id = check.__class__.__name__.lower().replace('check', '')

            self._checks[check.id] = check
            self._checks_by_category[check.category].append(check)
            self._check_classes[check.id] = type(check)

            # logger.info(f"Registered check: {check.id} (category: {check.category})")
        except Exception as e:
            logger.error(f"Error registering check {check}: {e}")

    def get_check(self, check_id: str) -> Optional[BaseCheck]:
        """
        Ottiene un controllo per ID.

        Args:
            check_id: ID del controllo

        Returns:
            Controllo richiesto o None se non trovato
        """
        return self._checks.get(check_id)

    def get_checks_by_category(self, category: str) -> List[BaseCheck]:
        """
        Ottiene tutti i controlli di una categoria.

        Args:
            category: Nome della categoria

        Returns:
            Lista di controlli della categoria
        """
        return self._checks_by_category.get(category, [])

    def get_all_checks(self) -> Dict[str, List[BaseCheck]]:
        """
        Ottiene tutti i controlli registrati organizzati per categoria.

        Returns:
            Dizionario con categorie come chiavi e liste di controlli come valori
        """
        return dict(self._checks_by_category)

    def get_all_checks_list(self) -> List[BaseCheck]:
        """
        Ottiene tutti i controlli registrati come lista.

        Returns:
            Lista di tutti i controlli
        """
        return list(self._checks.values())

    def get_categories(self) -> List[str]:
        """
        Ottiene tutte le categorie disponibili.

        Returns:
            Lista delle categorie
        """
        return list(self._checks_by_category.keys())

    def get_checks_for_os(self, os_type: str) -> List[BaseCheck]:
        """
        Ottiene i controlli compatibili con un OS.

        Args:
            os_type: Tipo di sistema operativo

        Returns:
            Lista di controlli compatibili
        """
        compatible_checks = []
        for check in self._checks.values():
            if os_type in check.supported_os:
                compatible_checks.append(check)
        return compatible_checks

    def execute_checks(
            self,
            context: Dict[str, any],
            check_ids: Optional[List[str]] = None,
            categories: Optional[List[str]] = None
    ) -> Dict[str, CheckResult]:
        """
        Esegue un insieme di controlli.

        Args:
            context: Contesto di esecuzione
            check_ids: Lista di ID specifici da eseguire (opzionale)
            categories: Lista di categorie da eseguire (opzionale)

        Returns:
            Dizionario con i risultati dei controlli
        """
        results = {}
        checks_to_run = []

        if check_ids:
            # Esegui controlli specifici
            for check_id in check_ids:
                check = self.get_check(check_id)
                if check:
                    checks_to_run.append(check)
                else:
                    logger.warning(f"Check {check_id} not found in registry")
        elif categories:
            # Esegui controlli per categorie
            for category in categories:
                checks_to_run.extend(self.get_checks_by_category(category))
        else:
            # Esegui tutti i controlli compatibili
            os_type = context.get("os_type", "unknown")
            checks_to_run = self.get_checks_for_os(os_type)

        # Rimuovi duplicati mantenendo l'ordine
        seen = set()
        unique_checks = []
        for check in checks_to_run:
            if check.id not in seen:
                seen.add(check.id)
                unique_checks.append(check)

        # Esegui i controlli
        # logger.info(f"Executing {len(unique_checks)} checks")
        for check in unique_checks:
            try:
                result = check.run(context)
                results[check.id] = result
            except Exception as e:
                logger.error(f"Unexpected error running check {check.id}: {e}")
                results[check.id] = CheckResult(
                    status=CheckStatus.ERROR,
                    message=f"Unexpected error: {str(e)}"
                )

        return results

    def get_registry_info(self) -> Dict[str, any]:
        """
        Ottiene informazioni sul registro.

        Returns:
            Informazioni sul registro
        """
        # Se non ci sono controlli, restituisci una struttura vuota ma consistente
        if not self._checks:
            return {
                "total_checks": 0,
                "categories": {},
                "available_checks": []
            }

        return {
            "total_checks": len(self._checks),
            "categories": {
                category: len(checks)
                for category, checks in self._checks_by_category.items()
            },
            "available_checks": [
                {
                    "id": check.id,
                    "name": check.name,
                    "category": check.category,
                    "severity": check.severity,
                    "supported_os": check.supported_os
                }
                for check in self._checks.values()
            ]
        }

    def clear(self) -> None:
        """Pulisce il registro."""
        self._checks.clear()
        self._checks_by_category.clear()
        self._check_classes.clear()
        # logger.info("Registry cleared")

    def __len__(self) -> int:
        return len(self._checks)

    def __str__(self) -> str:
        return f"CheckRegistry({len(self._checks)} checks, {len(self._checks_by_category)} categories)"