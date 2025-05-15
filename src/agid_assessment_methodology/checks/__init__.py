"""Base interfaces for security checks.

This module provides the base classes and interfaces for implementing
security checks for ABSC compliance.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field

from agid_assessment_methodology.core.engine import AssessmentResult, Target

logger = logging.getLogger(__name__)


class CheckCategory(str, Enum):
    """Categories of security checks."""

    INVENTORY = "inventory"  # ABSC 1.x
    VULNERABILITY = "vulnerability"  # ABSC 4.x
    MALWARE = "malware"  # ABSC 8.x
    AUTHENTICATION = "authentication"  # ABSC 2.x
    ADMIN_ACCESS = "admin_access"  # ABSC 5.x
    BACKUP = "backup"  # ABSC 13.x
    ENCRYPTION = "encryption"  # ABSC 3.x
    LOGGING = "logging"  # ABSC 10.x
    OTHER = "other"


class CheckPriority(str, Enum):
    """Priority levels for security checks."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BaseCheck(ABC):
    """Base class for all security checks."""

    # Class attributes to be defined by subclasses
    check_id: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    category: ClassVar[CheckCategory]
    priority: ClassVar[CheckPriority]
    absc_references: ClassVar[List[str]]
    supported_systems: ClassVar[Set[str]] = {"windows", "linux", "local"}

    def __init__(self, target: Target):
        """Initialize the check with a target.

        Args:
            target: Target system to check
        """
        self.target = target
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def run(self) -> AssessmentResult:
        """Run the check on the target system.

        Returns:
            Assessment result with check outcome
        """
        pass

    def get_remediation(self) -> str:
        """Get remediation guidance for failed checks.

        Returns:
            Remediation guidance text
        """
        return "No specific remediation guidance available."

    def create_result(
        self,
        status: bool,
        score: float,
        details: Dict[str, Any],
        evidence: Optional[str] = None,
        remediation: Optional[str] = None
    ) -> AssessmentResult:
        """Create an assessment result.

        Args:
            status: Whether the check passed (True) or failed (False)
            score: Compliance score (0.0-100.0)
            details: Detailed information about the check result
            evidence: Evidence supporting the result (optional)
            remediation: Remediation guidance (optional)

        Returns:
            Assessment result
        """
        return AssessmentResult(
            check_id=self.check_id,
            target=self.target.name,
            status=status,
            score=score,
            details=details,
            timestamp=datetime.now().isoformat(),
            evidence=evidence,
            remediation=remediation or self.get_remediation() if not status else None
        )


class CheckRegistry:
    """Registry for security checks."""

    _registry: Dict[str, type[BaseCheck]] = {}

    @classmethod
    def register(cls, check_class: type[BaseCheck]) -> type[BaseCheck]:
        """Register a check class.

        This method can be used as a decorator.

        Args:
            check_class: Check class to register

        Returns:
            The registered check class
        """
        cls._registry[check_class.check_id] = check_class
        logger.debug(f"Registered check: {check_class.check_id}")
        return check_class

    @classmethod
    def get_all_checks(cls) -> Dict[str, type[BaseCheck]]:
        """Get all registered checks.

        Returns:
            Dictionary of check IDs to check classes
        """
        return cls._registry.copy()

    @classmethod
    def get_check(cls, check_id: str) -> Optional[type[BaseCheck]]:
        """Get a specific check by ID.

        Args:
            check_id: ID of the check to get

        Returns:
            Check class or None if not found
        """
        return cls._registry.get(check_id)

    @classmethod
    def get_checks_by_category(cls, category: CheckCategory) -> Dict[str, type[BaseCheck]]:
        """Get all checks in a specific category.

        Args:
            category: Category to filter by

        Returns:
            Dictionary of check IDs to check classes in the category
        """
        return {
            check_id: check_class
            for check_id, check_class in cls._registry.items()
            if check_class.category == category
        }

    @classmethod
    def get_checks_by_priority(cls, priority: CheckPriority) -> Dict[str, type[BaseCheck]]:
        """Get all checks with a specific priority.

        Args:
            priority: Priority to filter by

        Returns:
            Dictionary of check IDs to check classes with the priority
        """
        return {
            check_id: check_class
            for check_id, check_class in cls._registry.items()
            if check_class.priority == priority
        }
