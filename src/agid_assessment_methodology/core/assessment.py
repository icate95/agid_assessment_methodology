"""Modulo Assessment per la valutazione dei risultati di sicurezza."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

# Importa utilities
from ..utils.logger import get_logger
from ..utils.reporting import ReportGenerator, ExportFormat

logger = get_logger(__name__)


class Assessment:
    """Classe principale per gestire le valutazioni di sicurezza."""

    def __init__(self, scan_results: Optional[Dict[str, Any]] = None):
        """
        Inizializza una nuova istanza di Assessment.

        Args:
            scan_results: Risultati di una scansione, se disponibili
        """
        self.scan_results = scan_results or {}
        self.assessment_results = {}
        self.compliance_levels = {
            "basic": {"required_checks": ["system_info", "basic_security"]},
            "standard": {"required_checks": ["system_info", "basic_security", "firewall"]},
            "advanced": {"required_checks": ["system_info", "basic_security", "firewall", "updates"]}
        }

    def load_scan_results(self, results: Dict[str, Any]) -> None:
        """
        Carica i risultati di una scansione.

        Args:
            results: Dizionario con i risultati della scansione
        """
        self.scan_results = results
        logger.info("Scan results loaded into assessment")

    def analyze_security_posture(self) -> Dict[str, Any]:
        """
        Analizza la postura di sicurezza basata sui risultati della scansione.

        Returns:
            Dizionario con l'analisi della sicurezza
        """
        if not self.scan_results:
            logger.warning("No scan results to analyze")
            return {"status": "error", "message": "No scan results available"}

        analysis = {
            "summary": {
                "total_checks": len(self.scan_results) - 1,  # -1 per scan_metadata
                "completed_checks": 0,
                "failed_checks": 0,
                "critical_issues": 0,
                "warnings": 0
            },
            "categories": {},
            "recommendations": []
        }

        # Analizza ogni categoria di controllo
        for check_name, check_result in self.scan_results.items():
            if check_name == "scan_metadata":
                continue

            category_analysis = self._analyze_check_result(check_name, check_result)
            analysis["categories"][check_name] = category_analysis

            # Aggiorna i contatori
            if category_analysis["status"] == "completed":
                analysis["summary"]["completed_checks"] += 1
            elif category_analysis["status"] == "failed":
                analysis["summary"]["failed_checks"] += 1

            # Aggiungi issues al totale
            analysis["summary"]["critical_issues"] += len(category_analysis.get("critical_issues", []))
            analysis["summary"]["warnings"] += len(category_analysis.get("warnings", []))

            # Aggiungi raccomandazioni
            if category_analysis.get("recommendations"):
                analysis["recommendations"].extend(category_analysis["recommendations"])

        # Calcola punteggio generale
        total_checks = analysis["summary"]["total_checks"]
        if total_checks > 0:
            success_rate = (analysis["summary"]["completed_checks"] / total_checks) * 100
            analysis["summary"]["success_rate"] = round(success_rate, 2)
        else:
            analysis["summary"]["success_rate"] = 0

        # Determina il livello di rischio
        analysis["summary"]["risk_level"] = self._calculate_risk_level(analysis["summary"])

        self.assessment_results = analysis
        return analysis

    def _analyze_check_result(self, check_name: str, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analizza il risultato di un singolo controllo.

        Args:
            check_name: Nome del controllo
            check_result: Risultato del controllo

        Returns:
            Analisi del controllo
        """
        # Gestisce sia il formato nuovo (con status, issues, etc.) che quello vecchio
        if isinstance(check_result, dict):
            status = check_result.get("status", "unknown")
            issues = check_result.get("issues", [])
        else:
            # Fallback per formati non previsti
            status = "unknown"
            issues = []

        analysis = {
            "status": status,
            "check_name": check_name,
            "critical_issues": [],
            "warnings": [],
            "recommendations": []
        }

        # Classifica gli issues per severità
        for issue in issues:
            if isinstance(issue, dict):
                severity = issue.get("severity", "medium")
                if severity in ["critical", "high"]:
                    analysis["critical_issues"].append(issue)
                else:
                    analysis["warnings"].append(issue)

        # Genera raccomandazioni base
        if status == "fail" or analysis["critical_issues"]:
            analysis["recommendations"].append({
                "check": check_name,
                "priority": "high" if analysis["critical_issues"] else "medium",
                "description": f"Review and address issues found in {check_name}"
            })

        return analysis

    def _calculate_risk_level(self, summary: Dict[str, Any]) -> str:
        """
        Calcola il livello di rischio basato sui risultati.

        Args:
            summary: Riepilogo dell'assessment

        Returns:
            Livello di rischio (low, medium, high, critical)
        """
        critical_issues = summary.get("critical_issues", 0)
        success_rate = summary.get("success_rate", 0)

        if critical_issues > 3 or success_rate < 50:
            return "critical"
        elif critical_issues > 1 or success_rate < 70:
            return "high"
        elif critical_issues > 0 or success_rate < 90:
            return "medium"
        else:
            return "low"

    def check_compliance(self, level: str = "basic") -> Dict[str, Any]:
        """
        Verifica la compliance rispetto a un livello specificato.

        Args:
            level: Livello di compliance (basic, standard, advanced)

        Returns:
            Risultato della verifica di compliance
        """
        if level not in self.compliance_levels:
            logger.error(f"Invalid compliance level: {level}")
            raise ValueError(f"Invalid compliance level: {level}")

        if not self.scan_results:
            logger.warning("No scan results available for compliance check")
            return {"status": "error", "message": "No scan results available"}

        required_checks = self.compliance_levels[level]["required_checks"]
        completed_checks = [check for check in required_checks if check in self.scan_results]

        compliance_result = {
            "level": level,
            "status": "compliant" if len(completed_checks) == len(required_checks) else "non_compliant",
            "required_checks": required_checks,
            "completed_checks": completed_checks,
            "missing_checks": [check for check in required_checks if check not in completed_checks],
            "compliance_percentage": round((len(completed_checks) / len(required_checks)) * 100, 2),
            "timestamp": datetime.now().isoformat()
        }

        return compliance_result

    def generate_report_summary(self) -> Dict[str, Any]:
        """
        Genera un riepilogo per il report.

        Returns:
            Riepilogo dell'assessment
        """
        if not self.assessment_results:
            # Se non abbiamo ancora analizzato, facciamolo ora
            self.analyze_security_posture()

        summary = {
            "assessment_timestamp": datetime.now().isoformat(),
            "target": self.scan_results.get("scan_metadata", {}).get("target", "unknown"),
            "overall_status": self.assessment_results.get("summary", {}).get("risk_level", "unknown"),
            "total_checks": self.assessment_results.get("summary", {}).get("total_checks", 0),
            "success_rate": self.assessment_results.get("summary", {}).get("success_rate", 0),
            "critical_issues": self.assessment_results.get("summary", {}).get("critical_issues", 0),
            "recommendations_count": len(self.assessment_results.get("recommendations", [])),
            "compliance": {
                "basic": self.check_compliance("basic"),
                "standard": self.check_compliance("standard"),
                "advanced": self.check_compliance("advanced")
            }
        }

        return summary

    def generate_report(
        self,
        output_path: str,
        format_type: str = "json",
        include_raw_data: bool = True
    ) -> Path:
        """
        Genera un report dell'assessment.

        Args:
            output_path: Percorso di output per il report
            format_type: Formato del report (json, csv, html, pdf)
            include_raw_data: Se includere i dati grezzi

        Returns:
            Percorso al file di report generato
        """
        if not self.assessment_results:
            self.analyze_security_posture()

        # Prepara i dati completi per il report
        report_data = {
            "summary": self.assessment_results.get("summary", {}),
            "categories": self.assessment_results.get("categories", {}),
            "recommendations": self.assessment_results.get("recommendations", []),
            "details": self.scan_results,
            "scan_metadata": self.scan_results.get("scan_metadata", {}),
            "compliance": {
                "basic": self.check_compliance("basic"),
                "standard": self.check_compliance("standard"),
                "advanced": self.check_compliance("advanced")
            }
        }

        # Genera il report
        generator = ReportGenerator()
        return generator.generate_report(
            report_data,
            output_path,
            format_type,
            include_raw_data=include_raw_data
        )

    def __str__(self) -> str:
        """Rappresentazione string dell'assessment."""
        if self.assessment_results:
            risk_level = self.assessment_results.get("summary", {}).get("risk_level", "unknown")
            return f"Assessment(risk_level='{risk_level}')"
        else:
            return "Assessment(not_analyzed)"

    def __repr__(self) -> str:
        """Rappresentazione dettagliata dell'assessment."""
        return f"Assessment(has_results={bool(self.scan_results)}, analyzed={bool(self.assessment_results)})"