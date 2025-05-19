"""Classe base per tutti i controlli di sicurezza."""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class CheckStatus(Enum):
    """Stato di un controllo."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class CheckResult:
    """Risultato di un controllo di sicurezza."""

    def __init__(
            self,
            status: CheckStatus,
            message: str = "",
            details: Optional[Dict[str, Any]] = None,
            issues: Optional[List[Dict[str, Any]]] = None,
            recommendations: Optional[List[str]] = None,
            score: Optional[float] = None
    ):
        """
        Inizializza un risultato di controllo.

        Args:
            status: Stato del controllo
            message: Messaggio descrittivo
            details: Dettagli aggiuntivi
            issues: Lista di problemi trovati
            recommendations: Lista di raccomandazioni
            score: Punteggio numerico (0-100)
        """
        self.status = status
        self.message = message
        self.details = details or {}
        self.issues = issues or []
        self.recommendations = recommendations or []
        self.score = score
        self.timestamp = datetime.now().isoformat()

    def add_issue(self, issue: Dict[str, Any]) -> None:
        """Aggiunge un problema al risultato."""
        self.issues.append(issue)

    def add_recommendation(self, recommendation: str) -> None:
        """Aggiunge una raccomandazione al risultato."""
        self.recommendations.append(recommendation)

    def to_dict(self) -> Dict[str, Any]:
        """Converte il risultato in dizionario."""
        return {
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "issues": self.issues,
            "recommendations": self.recommendations,
            "score": self.score,
            "timestamp": self.timestamp
        }

    def __str__(self) -> str:
        return f"CheckResult(status={self.status.value}, score={self.score})"


class BaseCheck(ABC):
    """Classe base per tutti i controlli di sicurezza."""

    def __init__(self):
        """Inizializza il controllo."""
        # Metadati del controllo
        self.id = self.__class__.__name__.lower().replace('check', '')
        self.name = "Base Security Check"
        self.description = "Base security check description"
        self.category = "general"
        self.severity = "medium"  # low, medium, high, critical
        self.supported_os = ["windows", "linux", "macos"]  # OS supportati

        # Stati interni
        self._logger = logger.getChild(self.id)
        self._executed = False
        self._last_result = None

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Esegue il controllo di sicurezza.

        Args:
            context: Contesto di esecuzione con informazioni sul sistema

        Returns:
            Risultato del controllo
        """
        pass

    def is_applicable(self, context: Dict[str, Any]) -> bool:
        """
        Determina se il controllo è applicabile al sistema corrente.

        Args:
            context: Contesto di esecuzione

        Returns:
            True se il controllo è applicabile
        """
        os_type = context.get("os_type", "unknown")
        return os_type in self.supported_os

    def run(self, context: Dict[str, Any]) -> CheckResult:
        """
        Esegue il controllo con gestione degli errori.

        Args:
            context: Contesto di esecuzione

        Returns:
            Risultato del controllo
        """
        self._logger.info(f"Executing check: {self.id}")

        try:
            # Verifica se il controllo è applicabile
            if not self.is_applicable(context):
                self._logger.info(f"Check {self.id} skipped - not applicable for {context.get('os_type')}")
                result = CheckResult(
                    status=CheckStatus.SKIPPED,
                    message=f"Check not applicable for {context.get('os_type', 'unknown')} systems"
                )
            else:
                # Esegue il controllo
                result = self.execute(context)

            self._executed = True
            self._last_result = result
            self._logger.info(f"Check {self.id} completed with status: {result.status.value}")
            return result

        except Exception as e:
            self._logger.error(f"Error executing check {self.id}: {str(e)}")
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Error executing check: {str(e)}",
                details={"error_type": type(e).__name__}
            )

    def get_metadata(self) -> Dict[str, Any]:
        """
        Restituisce i metadati del controllo.

        Returns:
            Dizionario con i metadati
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "supported_os": self.supported_os,
            "executed": self._executed,
            "last_status": self._last_result.status.value if self._last_result else None
        }

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(id='{self.id}', category='{self.category}')"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id='{self.id}', executed={self._executed})"