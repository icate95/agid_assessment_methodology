"""Storage utilities for assessment results.

This module provides storage capabilities for assessment results,
supporting both SQLite and PostgreSQL backends.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import sqlalchemy
from pydantic import BaseModel
from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        String, Text, create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker

from agid_assessment_methodology.config.settings import settings
from agid_assessment_methodology.core.engine import AssessmentResult, AssessmentSummary

logger = logging.getLogger(__name__)

Base = declarative_base()


class StorageType(str, Enum):
    """Type of storage backend."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"


class DBAssessment(Base):
    """Assessment summary database model."""

    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False, index=True)
    target_type = Column(String, nullable=False)
    total_checks = Column(Integer, nullable=False)
    passed_checks = Column(Integer, nullable=False)
    failed_checks = Column(Integer, nullable=False)
    overall_score = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)

    results = relationship("DBAssessmentResult", back_populates="assessment", cascade="all, delete-orphan")

    def to_dict(self) -> Dict[str, Any]:
        """Convert the database model to a dictionary.

        Returns:
            Dictionary representation of the assessment
        """
        return {
            "id": self.id,
            "target": self.target,
            "target_type": self.target_type,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "overall_score": self.overall_score,
            "timestamp": self.timestamp.isoformat(),
            "results": [result.to_dict() for result in self.results]
        }


class DBAssessmentResult(Base):
    """Assessment result database model."""

    __tablename__ = "assessment_results"

    id = Column(Integer, primary_key=True)
    assessment_id = Column(Integer, ForeignKey("assessments.id"), nullable=False)
    check_id = Column(String, nullable=False, index=True)
    status = Column(Boolean, nullable=False)
    score = Column(Float, nullable=False)
    details = Column(Text, nullable=False)  # JSON string
    timestamp = Column(DateTime, nullable=False)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    assessment = relationship("DBAssessment", back_populates="results")

    def to_dict(self) -> Dict[str, Any]:
        """Convert the database model to a dictionary.

        Returns:
            Dictionary representation of the assessment result
        """
        return {
            "id": self.id,
            "check_id": self.check_id,
            "status": self.status,
            "score": self.score,
            "details": json.loads(self.details),
            "timestamp": self.timestamp.isoformat(),
            "evidence": self.evidence,
            "remediation": self.remediation
        }


class AssessmentStore:
    """Storage for assessment results."""

    def __init__(self, storage_type: Optional[StorageType] = None, connection_string: Optional[str] = None):
        """Initialize the assessment store.

        Args:
            storage_type: Type of storage backend to use (default from settings)
            connection_string: Database connection string (default from settings)
        """
        self.storage_type = storage_type or StorageType(settings.storage_type)
        self.connection_string = connection_string or self._get_connection_string()
        self.engine = create_engine(self.connection_string)
        self.Session = sessionmaker(bind=self.engine)

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)
        logger.info(f"Initialized assessment store with {self.storage_type} backend")

    def _get_connection_string(self) -> str:
        """Get the database connection string based on storage type.

        Returns:
            Database connection string
        """
        if self.storage_type == StorageType.SQLITE:
            db_path = settings.sqlite_path or os.path.join(Path.home(), ".agid_assessment", "assessments.db")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            return f"sqlite:///{db_path}"
        elif self.storage_type == StorageType.POSTGRESQL:
            return (
                f"postgresql://{settings.pg_user}:{settings.pg_password}@"
                f"{settings.pg_host}:{settings.pg_port}/{settings.pg_database}"
            )
        else:
            raise ValueError(f"Unsupported storage type: {self.storage_type}")

    def store_assessment(self, summary: AssessmentSummary) -> int:
        """Store an assessment summary in the database.

        Args:
            summary: Assessment summary to store

        Returns:
            ID of the stored assessment
        """
        with self.Session() as session:
            timestamp = datetime.fromisoformat(summary.timestamp)

            # Create the assessment
            db_assessment = DBAssessment(
                target=summary.target,
                target_type=summary.target_type,
                total_checks=summary.total_checks,
                passed_checks=summary.passed_checks,
                failed_checks=summary.failed_checks,
                overall_score=summary.overall_score,
                timestamp=timestamp
            )

            # Create the assessment results
            for result in summary.results:
                result_timestamp = datetime.fromisoformat(result.timestamp)
                db_result = DBAssessmentResult(
                    check_id=result.check_id,
                    status=result.status,
                    score=result.score,
                    details=json.dumps(result.details),
                    timestamp=result_timestamp,
                    evidence=result.evidence,
                    remediation=result.remediation
                )
                db_assessment.results.append(db_result)

            # Add to the database
            session.add(db_assessment)
            session.commit()

            logger.info(f"Stored assessment for target {summary.target} with ID {db_assessment.id}")
            return db_assessment.id

    def get_assessment(self, assessment_id: int) -> Optional[Dict[str, Any]]:
        """Get an assessment by ID.

        Args:
            assessment_id: ID of the assessment to get

        Returns:
            Assessment data or None if not found
        """
        with self.Session() as session:
            assessment = session.query(DBAssessment).filter(DBAssessment.id == assessment_id).first()
            if assessment:
                return assessment.to_dict()
            return None

    def get_assessments(self, target: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get assessments, optionally filtered by target.

        Args:
            target: Target to filter by, or None for all targets
            limit: Maximum number of assessments to return

        Returns:
            List of assessment data
        """
        with self.Session() as session:
            query = session.query(DBAssessment)
            if target:
                query = query.filter(DBAssessment.target == target)

            # Order by timestamp desc and limit
            query = query.order_by(DBAssessment.timestamp.desc()).limit(limit)

            return [assessment.to_dict() for assessment in query.all()]

    def get_latest_assessment(self, target: str) -> Optional[Dict[str, Any]]:
        """Get the latest assessment for a target.

        Args:
            target: Target to get the latest assessment for

        Returns:
            Latest assessment data or None if no assessments found
        """
        assessments = self.get_assessments(target, limit=1)
        return assessments[0] if assessments else None

    def delete_assessment(self, assessment_id: int) -> bool:
        """Delete an assessment by ID.

        Args:
            assessment_id: ID of the assessment to delete

        Returns:
            True if the assessment was deleted, False otherwise
        """
        with self.Session() as session:
            assessment = session.query(DBAssessment).filter(DBAssessment.id == assessment_id).first()
            if assessment:
                session.delete(assessment)
                session.commit()
                logger.info(f"Deleted assessment with ID {assessment_id}")
                return True
            logger.warning(f"Assessment with ID {assessment_id} not found")
            return False
