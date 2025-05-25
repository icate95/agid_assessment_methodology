"""Sistema di generazione report per AGID Assessment Methodology."""

import json
import csv
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from enum import Enum
import tempfile
import os

# from reportlab.pdfgen import canvas as reportlab_canvas
# import reportlab.pdfgen.canvas
from reportlab.pdfgen import canvas as canvas

logger = logging.getLogger(__name__)


# File: src/agid_assessment_methodology/utils/reporting.py
# Aggiungere questa funzione all'inizio del file, dopo gli import

def _get_pdf_library():
    """Determina quale libreria PDF usare in base alla piattaforma."""
    import platform

    # Su macOS, prova prima reportlab (più stabile)
    if platform.system() == "Darwin":
        try:
            import reportlab
            return "reportlab"
        except ImportError:
            pass

        try:
            import weasyprint
            return "weasyprint"
        except ImportError:
            pass
    else:
        # Su altre piattaforme, prova prima weasyprint
        try:
            import weasyprint
            return "weasyprint"
        except ImportError:
            pass

        try:
            import reportlab
            return "reportlab"
        except ImportError:
            pass

    return None

class ExportFormat(Enum):
    """Formati di esportazione supportati."""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PDF = "pdf"
    XML = "xml"

    @classmethod
    def from_string(cls, format_str: str) -> 'ExportFormat':
        """
        Converte una stringa in un formato di esportazione.

        Args:
            format_str: Stringa rappresentante il formato

        Returns:
            Formato di esportazione

        Raises:
            ValueError: Se il formato non è supportato
        """
        format_str = format_str.lower()
        for fmt in cls:
            if fmt.value == format_str:
                return fmt

        raise ValueError(f"Unsupported export format: {format_str}")


class ReportGenerator:
    """Generatore di report per assessment di sicurezza."""

    def __init__(self, template_dir: Optional[str] = None):
        """
        Inizializza il generatore di report.

        Args:
            template_dir: Directory contenente i template personalizzati
        """
        self.template_dir = Path(template_dir) if template_dir else None
        self._ensure_template_dir()

    def _ensure_template_dir(self):
        """Assicura che la directory dei template esista."""
        if self.template_dir:
            self.template_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        assessment_data: Dict[str, Any],
        output_path: Union[str, Path],
        format_type: Union[ExportFormat, str],
        template_name: Optional[str] = None,
        include_raw_data: bool = False
    ) -> Path:
        """
        Genera un report dall'assessment.

        Args:
            assessment_data: Dati dell'assessment
            output_path: Percorso di output per il report
            format_type: Formato del report
            template_name: Nome del template da utilizzare
            include_raw_data: Se includere i dati grezzi nel report

        Returns:
            Percorso al file di report generato
        """
        # Converte il formato se necessario
        if isinstance(format_type, str):
            format_type = ExportFormat.from_string(format_type)

        output_path = Path(output_path)

        # Assicura che la directory di output esista
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Aggiunge l'estensione se mancante
        if not output_path.suffix:
            output_path = output_path.with_suffix(f".{format_type.value}")

        # Prepara i dati per il report
        report_data = self._prepare_report_data(assessment_data, include_raw_data)

        # Genera il report nel formato richiesto
        if format_type == ExportFormat.JSON:
            return self._generate_json_report(report_data, output_path)
        elif format_type == ExportFormat.CSV:
            return self._generate_csv_report(report_data, output_path)
        elif format_type == ExportFormat.HTML:
            return self._generate_html_report(report_data, output_path, template_name)
        elif format_type == ExportFormat.PDF:
            return self._generate_pdf_report(report_data, output_path, template_name)
        elif format_type == ExportFormat.XML:
            return self._generate_xml_report(report_data, output_path)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _prepare_report_data(self, assessment_data: Dict[str, Any], include_raw_data: bool) -> Dict[str, Any]:
        """
        Prepara i dati per la generazione del report.

        Args:
            assessment_data: Dati dell'assessment
            include_raw_data: Se includere i dati grezzi

        Returns:
            Dati preparati per il report
        """
        report_data = {
            "metadata": {
                "report_generated": datetime.now().isoformat(),
                "report_version": "1.0",
                "tool_version": "0.1.0"
            },
            "executive_summary": self._create_executive_summary(assessment_data),
            "detailed_results": self._format_detailed_results(assessment_data),
            "recommendations": self._extract_recommendations(assessment_data),
            "compliance_summary": self._create_compliance_summary(assessment_data),
            "risk_analysis": self._create_risk_analysis(assessment_data)
        }

        if include_raw_data:
            report_data["raw_data"] = assessment_data

        return report_data

    def _create_executive_summary(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Crea il riepilogo esecutivo."""
        summary = assessment_data.get("summary", {})
        scan_metadata = assessment_data.get("scan_metadata", {})

        return {
            "target_system": scan_metadata.get("target", "Unknown"),
            "scan_timestamp": scan_metadata.get("timestamp"),
            "total_checks": summary.get("total_checks", 0),
            "success_rate": summary.get("success_rate", 0),
            "overall_risk_level": summary.get("risk_level", "unknown"),
            "critical_issues": summary.get("critical_issues", 0),
            "high_priority_recommendations": len([
                r for r in assessment_data.get("recommendations", [])
                if r.get("priority") == "high"
            ])
        }

    def _format_detailed_results(self, assessment_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formatta i risultati dettagliati per categoria."""
        detailed_results = []
        categories = assessment_data.get("categories", {})

        for category_name, category_data in categories.items():
            category_result = {
                "category": category_name,
                "status": category_data.get("status", "unknown"),
                "checks": []
            }

            # Estrae i dettagli dai risultati grezzi se disponibili
            if "details" in assessment_data:
                category_checks = assessment_data["details"].get(category_name, {})
                for check_name, check_data in category_checks.items():
                    if check_name != "scan_metadata":
                        # Verifica che check_data sia un dizionario
                        if isinstance(check_data, dict):
                            check_result = {
                                "name": check_name,
                                "status": check_data.get("status", "unknown"),
                                "score": check_data.get("score"),
                                "issues_count": len(check_data.get("issues", [])),
                                "recommendations_count": len(check_data.get("recommendations", []))
                            }
                        else:
                            # Se check_data non è un dizionario, crea una struttura base
                            check_result = {
                                "name": check_name,
                                "status": "unknown",
                                "score": None,
                                "issues_count": 0,
                                "recommendations_count": 0
                            }

                        category_result["checks"].append(check_result)

            detailed_results.append(category_result)

        return detailed_results

    def _extract_recommendations(self, assessment_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Estrae e prioritizza le raccomandazioni."""
        recommendations = assessment_data.get("recommendations", [])

        # Ordina per priorità
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_recommendations = sorted(
            recommendations,
            key=lambda x: priority_order.get(x.get("priority", "low"), 99)
        )

        return sorted_recommendations

    def _create_compliance_summary(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Crea il riepilogo della compliance."""
        # Cerca informazioni di compliance nei dati
        compliance_data = {}

        # Se abbiamo un assessment completo, estrae i dati di compliance
        if "compliance" in assessment_data:
            compliance_data = assessment_data["compliance"]

        return {
            "basic_compliance": compliance_data.get("basic", {}),
            "standard_compliance": compliance_data.get("standard", {}),
            "advanced_compliance": compliance_data.get("advanced", {}),
            "overall_compliance_score": self._calculate_overall_compliance(compliance_data)
        }

    def _create_risk_analysis(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Crea l'analisi dei rischi."""
        summary = assessment_data.get("summary", {})

        return {
            "overall_risk_level": summary.get("risk_level", "unknown"),
            "risk_factors": {
                "critical_issues": summary.get("critical_issues", 0),
                "failed_checks": summary.get("failed_checks", 0),
                "success_rate": summary.get("success_rate", 0)
            },
            "risk_mitigation_priority": self._prioritize_risks(assessment_data)
        }

    def _calculate_overall_compliance(self, compliance_data: Dict[str, Any]) -> float:
        """Calcola il punteggio complessivo di compliance."""
        if not compliance_data:
            return 0.0

        total_score = 0.0
        count = 0

        for level_data in compliance_data.values():
            if isinstance(level_data, dict) and "compliance_percentage" in level_data:
                total_score += level_data["compliance_percentage"]
                count += 1

        return round(total_score / count, 2) if count > 0 else 0.0

    def _prioritize_risks(self, assessment_data: Dict[str, Any]) -> List[str]:
        """Prioritizza i rischi per la mitigazione."""
        priorities = []

        categories = assessment_data.get("categories", {})
        for category, data in categories.items():
            if data.get("critical_issues"):
                priorities.append(f"Address critical issues in {category}")
            elif data.get("status") == "failed":
                priorities.append(f"Review failed checks in {category}")

        return priorities[:5]  # Top 5 priorità

    def _generate_json_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Genera un report in formato JSON."""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            logger.info(f"JSON report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise

    def _generate_csv_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Genera un report in formato CSV."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Header
                writer.writerow(["Report Generated", report_data["metadata"]["report_generated"]])
                writer.writerow([])

                # Executive Summary
                writer.writerow(["EXECUTIVE SUMMARY"])
                summary = report_data["executive_summary"]
                for key, value in summary.items():
                    writer.writerow([key.replace('_', ' ').title(), value])
                writer.writerow([])

                # Detailed Results
                writer.writerow(["DETAILED RESULTS"])
                writer.writerow(
                    ["Category", "Status", "Check Name", "Check Status", "Score", "Issues", "Recommendations"])

                for category in report_data["detailed_results"]:
                    category_name = category["category"]
                    category_status = category["status"]

                    if not category["checks"]:
                        writer.writerow([category_name, category_status, "", "", "", "", ""])
                    else:
                        for i, check in enumerate(category["checks"]):
                            if i == 0:
                                writer.writerow([
                                    category_name, category_status,
                                    check["name"], check["status"],
                                    check.get("score", ""), check.get("issues_count", ""),
                                    check.get("recommendations_count", "")
                                ])
                            else:
                                writer.writerow([
                                    "", "",
                                    check["name"], check["status"],
                                    check.get("score", ""), check.get("issues_count", ""),
                                    check.get("recommendations_count", "")
                                ])
                writer.writerow([])

                # Recommendations
                writer.writerow(["RECOMMENDATIONS"])
                writer.writerow(["Priority", "Check", "Description"])
                for rec in report_data["recommendations"]:
                    writer.writerow([
                        rec.get("priority", ""),
                        rec.get("check", ""),
                        rec.get("description", "")
                    ])

            logger.info(f"CSV report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")
            raise

    def _generate_html_report(self, report_data: Dict[str, Any], output_path: Path, template_name: Optional[str] = None) -> Path:
        """Genera un report in formato HTML."""
        try:
            # Template HTML di base
            html_template = self._get_html_template(template_name)

            # Sostituisce i placeholder con i dati reali
            html_content = html_template.format(
                title="AGID Security Assessment Report",
                generated_date=report_data["metadata"]["report_generated"],
                target=report_data["executive_summary"]["target_system"],
                risk_level=report_data["executive_summary"]["overall_risk_level"],
                success_rate=report_data["executive_summary"]["success_rate"],
                total_checks=report_data["executive_summary"]["total_checks"],
                critical_issues=report_data["executive_summary"]["critical_issues"],
                detailed_results=self._format_html_detailed_results(report_data["detailed_results"]),
                recommendations=self._format_html_recommendations(report_data["recommendations"]),
                compliance_summary=self._format_html_compliance(report_data["compliance_summary"])
            )

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise

    def _generate_pdf_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Genera un report in formato PDF."""
        pdf_lib = _get_pdf_library()

        if pdf_lib == "reportlab":
            return self._generate_pdf_with_reportlab(report_data, output_path)
        elif pdf_lib == "weasyprint":
            return self._generate_pdf_with_weasyprint(report_data, output_path)
        else:
            # Fallback: crea PDF semplice con testo
            logger.warning("No PDF library available, creating text-based PDF")
            return self._generate_simple_pdf(report_data, output_path)

    def _generate_pdf_with_reportlab(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Genera PDF usando reportlab (più semplice, sempre funziona)."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            # Crea documento
            doc = SimpleDocTemplate(str(output_path), pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Titolo
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=1  # Center
            )
            story.append(Paragraph("Security Assessment Report", title_style))
            story.append(Spacer(1, 20))

            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            exec_summary = report_data.get("executive_summary", {})

            summary_data = [
                ["Risk Level", exec_summary.get("overall_risk_level", "N/A")],
                ["Total Checks", str(exec_summary.get("total_checks", 0))],
                ["Passed Checks", str(exec_summary.get("passed_checks", 0))],
                ["Failed Checks", str(exec_summary.get("failed_checks", 0))],
                ["Critical Issues", str(exec_summary.get("critical_issues", 0))]
            ]

            summary_table = Table(summary_data)
            summary_table.setStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ])
            story.append(summary_table)
            story.append(Spacer(1, 20))

            # Compliance Summary
            story.append(Paragraph("Compliance Summary", styles['Heading2']))
            compliance_data = report_data.get("compliance_summary", {})

            compliance_table_data = [["Level", "Score", "Status"]]
            for level in ["basic", "standard", "advanced"]:
                level_data = compliance_data.get(f"{level}_compliance", {})
                compliance_table_data.append([
                    level.title(),
                    f"{level_data.get('compliance_percentage', 0):.1f}%",
                    "✓" if level_data.get('compliance_percentage', 0) >= 80 else "✗"
                ])

            compliance_table = Table(compliance_table_data)
            compliance_table.setStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ])
            story.append(compliance_table)
            story.append(Spacer(1, 20))

            # Recommendations
            recommendations = report_data.get("recommendations", [])
            if recommendations:
                story.append(Paragraph("Top Recommendations", styles['Heading2']))
                for i, rec in enumerate(recommendations[:5]):  # Top 5
                    rec_text = f"{i + 1}. [{rec.get('priority', 'Medium')}] {rec.get('description', 'N/A')}"
                    story.append(Paragraph(rec_text, styles['Normal']))
                    story.append(Spacer(1, 6))

            # Genera PDF
            doc.build(story)
            logger.info(f"PDF report generated with reportlab: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error generating PDF with reportlab: {str(e)}")
            raise

    def _generate_simple_pdf(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Crea un PDF semplice quando nessuna libreria PDF è disponibile."""
        try:
            # Crea un file di testo che simula un PDF
            with open(output_path, 'w') as f:
                f.write("SECURITY ASSESSMENT REPORT\n")
                f.write("=" * 50 + "\n\n")

                # Executive Summary
                exec_summary = report_data.get("executive_summary", {})
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Risk Level: {exec_summary.get('overall_risk_level', 'N/A')}\n")
                f.write(f"Total Checks: {exec_summary.get('total_checks', 0)}\n")
                f.write(f"Passed: {exec_summary.get('passed_checks', 0)}\n")
                f.write(f"Failed: {exec_summary.get('failed_checks', 0)}\n\n")

                # Compliance
                f.write("COMPLIANCE SUMMARY\n")
                f.write("-" * 20 + "\n")
                compliance = report_data.get("compliance_summary", {})
                f.write(f"Overall Score: {compliance.get('overall_compliance_score', 0):.1f}%\n\n")

                # Note
                f.write("NOTE: This is a text-based report.\n")
                f.write("Install 'reportlab' or 'weasyprint' for proper PDF generation.\n")
                f.write("Command: pip install reportlab\n")

            logger.warning(f"Created simple text-based PDF: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error creating simple PDF: {str(e)}")
            raise

    def _generate_xml_report(self, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Genera un report in formato XML."""
        try:
            import xml.etree.ElementTree as ET

            # Crea l'elemento root
            root = ET.Element("security_assessment_report")

            # Metadata
            metadata = ET.SubElement(root, "metadata")
            for key, value in report_data["metadata"].items():
                elem = ET.SubElement(metadata, key)
                elem.text = str(value)

            # Executive Summary
            exec_summary = ET.SubElement(root, "executive_summary")
            for key, value in report_data["executive_summary"].items():
                elem = ET.SubElement(exec_summary, key)
                elem.text = str(value)

            # Detailed Results
            detailed = ET.SubElement(root, "detailed_results")
            for category in report_data["detailed_results"]:
                cat_elem = ET.SubElement(detailed, "category")
                cat_elem.set("name", category["category"])
                cat_elem.set("status", category["status"])

                for check in category["checks"]:
                    check_elem = ET.SubElement(cat_elem, "check")
                    check_elem.set("name", check["name"])
                    check_elem.set("status", check["status"])
                    if check.get("score") is not None:
                        check_elem.set("score", str(check["score"]))

            # Recommendations
            recommendations = ET.SubElement(root, "recommendations")
            for rec in report_data["recommendations"]:
                rec_elem = ET.SubElement(recommendations, "recommendation")
                rec_elem.set("priority", rec.get("priority", ""))
                rec_elem.set("check", rec.get("check", ""))
                rec_elem.text = rec.get("description", "")

            # Scrive il file XML
            tree = ET.ElementTree(root)

            # Fallback per ET.indent (non disponibile in Python < 3.9)
            if hasattr(ET, 'indent'):
                ET.indent(tree, space="  ", level=0)
            else:
                # Implementazione manuale dell'indentazione per Python < 3.9
                self._indent_xml(root, level=0)

            # Scrivi il file
            tree.write(output_path, encoding='utf-8', xml_declaration=True)

            logger.info(f"XML report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error generating XML report: {str(e)}")
            raise

    def _indent_xml(self, elem, level=0):
        """Indentazione manuale per XML (fallback per Python < 3.9)."""
        indent = "\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = indent + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = indent
            for elem in elem:
                self._indent_xml(elem, level + 1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = indent
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = indent

    def _get_html_template(self, template_name: Optional[str] = None) -> str:
        """Ottiene il template HTML."""
        if template_name and self.template_dir:
            template_path = self.template_dir / f"{template_name}.html"
            if template_path.exists():
                return template_path.read_text(encoding='utf-8')

        # Template HTML di default
        return """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
        .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .risk-critical {{ color: #dc3545; font-weight: bold; }}
        .risk-high {{ color: #fd7e14; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        .risk-low {{ color: #28a745; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .status-pass {{ color: #28a745; }}
        .status-fail {{ color: #dc3545; }}
        .status-warning {{ color: #ffc107; }}
        .footer {{ margin-top: 40px; text-align: center; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Generated: {generated_date}</p>
        <p>Target System: {target}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Overall Risk Level</h3>
                <p class="risk-{risk_level}">{risk_level}</p>
            </div>
            <div class="summary-card">
                <h3>Success Rate</h3>
                <p>{success_rate}%</p>
            </div>
            <div class="summary-card">
                <h3>Total Checks</h3>
                <p>{total_checks}</p>
            </div>
            <div class="summary-card">
                <h3>Critical Issues</h3>
                <p class="risk-critical">{critical_issues}</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Detailed Results</h2>
        {detailed_results}
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        {recommendations}
    </div>

    <div class="section">
        <h2>Compliance Summary</h2>
        {compliance_summary}
    </div>

    <div class="footer">
        <p>Report generated by AGID Assessment Methodology v0.1.0</p>
    </div>
</body>
</html>
        """

    def _format_html_detailed_results(self, detailed_results: List[Dict[str, Any]]) -> str:
        """Formatta i risultati dettagliati per HTML."""
        html = "<table><tr><th>Category</th><th>Status</th><th>Checks</th></tr>"

        for category in detailed_results:
            checks_count = len(category["checks"])
            status_class = f"status-{category['status'].lower()}"

            html += f"""
            <tr>
                <td>{category['category'].title()}</td>
                <td class="{status_class}">{category['status'].title()}</td>
                <td>{checks_count} checks</td>
            </tr>
            """

        html += "</table>"
        return html

    def _format_html_recommendations(self, recommendations: List[Dict[str, Any]]) -> str:
        """Formatta le raccomandazioni per HTML."""
        if not recommendations:
            return "<p>No specific recommendations at this time.</p>"

        html = "<table><tr><th>Priority</th><th>Check</th><th>Description</th></tr>"

        for rec in recommendations:
            priority = rec.get("priority", "medium")
            priority_class = f"risk-{priority}"

            html += f"""
            <tr>
                <td class="{priority_class}">{priority.title()}</td>
                <td>{rec.get('check', '')}</td>
                <td>{rec.get('description', '')}</td>
            </tr>
            """

        html += "</table>"
        return html

    def _format_html_compliance(self, compliance_summary: Dict[str, Any]) -> str:
        """Formatta il riepilogo di compliance per HTML."""
        html = "<table><tr><th>Compliance Level</th><th>Status</th><th>Percentage</th></tr>"

        levels = ["basic", "standard", "advanced"]
        for level in levels:
            level_data = compliance_summary.get(f"{level}_compliance", {})
            if level_data:
                status = level_data.get("status", "unknown")
                percentage = level_data.get("compliance_percentage", 0)
                status_class = "status-pass" if status == "compliant" else "status-fail"

                html += f"""
                <tr>
                    <td>{level.title()}</td>
                    <td class="{status_class}">{status}</td>
                    <td>{percentage}%</td>
                </tr>
                """

        overall_score = compliance_summary.get("overall_compliance_score", 0)
        html += f"""
        <tr style="border-top: 2px solid #333; font-weight: bold;">
            <td>Overall</td>
            <td>-</td>
            <td>{overall_score}%</td>
        </tr>
        """

        html += "</table>"
        return html


def generate_quick_report(
    assessment_data: Dict[str, Any],
    output_dir: str = "reports",
    report_name: Optional[str] = None
) -> List[Path]:
    """
    Genera rapidamente report in tutti i formati supportati.

    Args:
        assessment_data: Dati dell'assessment
        output_dir: Directory di output
        report_name: Nome base per i file (opzionale)

    Returns:
        Lista dei percorsi ai file generati
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not report_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = assessment_data.get("scan_metadata", {}).get("target", "unknown")
        report_name = f"security_assessment_{target}_{timestamp}"

    generator = ReportGenerator()
    generated_files = []

    formats = [ExportFormat.JSON, ExportFormat.CSV, ExportFormat.HTML]

    for fmt in formats:
        try:
            output_path = output_dir / f"{report_name}.{fmt.value}"
            generated_file = generator.generate_report(
                assessment_data,
                output_path,
                fmt,
                include_raw_data=(fmt == ExportFormat.JSON)
            )
            generated_files.append(generated_file)
        except Exception as e:
            logger.error(f"Error generating {fmt.value} report: {str(e)}")

    return generated_files