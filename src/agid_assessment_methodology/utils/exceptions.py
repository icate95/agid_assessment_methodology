"""Custom exceptions for the AGID assessment methodology.

This module provides custom exceptions used throughout the application.
"""

from __future__ import annotations


class AssessmentError(Exception):
    """Base exception for assessment errors."""
    pass


class ConnectionError(AssessmentError):
    """Exception raised for connection errors."""
    pass


class SchedulerError(AssessmentError):
    """Exception raised for scheduler errors."""
    pass


class ReportingError(AssessmentError):
    """Exception raised for reporting errors."""
    pass


class NotifierError(AssessmentError):
    """Exception raised for notifier errors."""
    pass


class CheckError(AssessmentError):
    """Exception raised for check errors."""
    pass


class ValidationError(AssessmentError):
    """Exception raised for validation errors."""
    pass


class ConfigurationError(AssessmentError):
    """Exception raised for configuration errors."""
    pass
