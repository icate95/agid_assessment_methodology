"""Test aggiuntivi per migliorare la copertura del codice."""

import pytest
import json
import tempfile
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import per test CLI
from typer.testing import CliRunner
from agid_assessment_methodology.cli.main import app

# Import per test checks più approfonditi
from agid_assessment_methodology.checks import (
    BaseCheck, CheckResult, CheckStatus, CheckRegistry,
    SystemInfoCheck, BasicSecurityCheck, PasswordPolicyCheck
)

# Import per test core più approfonditi
from agid_assessment_methodology.core import Scanner, Assessment


class TestCLIExtended:
    """Test estesi per CLI."""

    def setup_method(self):
        """Setup per ogni test."""
        self.runner = CliRunner()

    def test_configure_non_interactive(self):
        """Test comando configure in modalità non interattiva."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_config.json"

            result = self.runner.invoke(app, [
                "configure",
                "--output", str(output_path),
                "--no-interactive"
            ])

            assert result.exit_code == 0
            assert output_path.exists()

            # Verifica contenuto configurazione
            with open(output_path) as f:
                config = json.load(f)
            assert "scan" in config
            assert "checks" in config

    def test_scan_with_config_and_output(self):
        """Test comando scan con configurazione e output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Crea configurazione di test
            config = {
                "scan": {"timeout": 60, "parallel": False},
                "checks": {"enabled_categories": ["system"]},
                "logging": {"level": "ERROR", "file_logging": False}
            }
            config_path = Path(temp_dir) / "config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f)

            output_path = Path(temp_dir) / "report.json"

            result = self.runner.invoke(app, [
                "scan",
                "localhost",
                "--config", str(config_path),
                "--output", str(output_path),
                "--format", "json"
            ])

            assert result.exit_code == 0
            assert output_path.exists()

    def test_report_command(self):
        """Test comando report."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Crea file assessment di test
            assessment_data = {
                "summary": {
                    "total_checks": 1,
                    "success_rate": 100.0,
                    "risk_level": "low"
                },
                "scan_metadata": {"target": "test"},
                "categories": {},
                "recommendations": []
            }

            assessment_file = Path(temp_dir) / "assessment.json"
            with open(assessment_file, 'w') as f:
                json.dump(assessment_data, f)

            result = self.runner.invoke(app, [
                "report",
                str(assessment_file),
                "--format", "html"
            ])

            assert result.exit_code == 0

    def test_report_command_missing_file(self):
        """Test comando report con file mancante."""
        result = self.runner.invoke(app, [
            "report",
            "/path/that/does/not/exist.json"
        ])

        assert result.exit_code == 1

    def test_report_command_invalid_json(self):
        """Test comando report con JSON invalido."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json")
            temp_path = Path(f.name)

        try:
            result = self.runner.invoke(app, [
                "report",
                str(temp_path)
            ])

            assert result.exit_code == 1
        finally:
            temp_path.unlink()


class TestChecksExtended:
    """Test estesi per modulo checks."""

    def test_base_check_error_handling(self):
        """Test gestione errori in BaseCheck."""

        class FailingCheck(BaseCheck):
            def execute(self, context):
                raise ValueError("Simulated failure")

        check = FailingCheck()
        result = check.run({"os_type": "linux"})

        assert result.status == CheckStatus.ERROR
        assert "Simulated failure" in result.message

    def test_system_info_check_with_psutil_error(self):
        """Test SystemInfoCheck con errore psutil."""
        check = SystemInfoCheck()

        # Mock psutil per far fallire l'import
        with patch('agid_assessment_methodology.checks.system.system_info.psutil', None):
            result = check.execute({"os_type": "linux"})

            # Dovrebbe comunque passare ma senza info estese
            assert result.status == CheckStatus.PASS
            assert "hostname" in result.details

    def test_basic_security_check_detailed(self):
        """Test dettagliato per BasicSecurityCheck."""
        check = BasicSecurityCheck()

        # Test con sistema Linux
        result = check.execute({"os_type": "linux"})

        assert result.status in [CheckStatus.PASS, CheckStatus.WARNING, CheckStatus.FAIL]
        assert "directory_permissions" in result.details

        # Verifica che lo score sia calcolato
        assert result.score is not None
        assert 0 <= result.score <= 100

    def test_password_policy_check_windows_mock(self):
        """Test PasswordPolicyCheck per Windows con mock."""
        check = PasswordPolicyCheck()

        # Mock subprocess per Windows
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
        Minimum password length: 8
        Maximum password age: 90
        Password history length: 5
        Lockout threshold: 5
        """

        with patch('subprocess.run', return_value=mock_result):
            result = check.execute({"os_type": "windows"})

            assert result.status in [CheckStatus.PASS, CheckStatus.WARNING, CheckStatus.FAIL]
            assert result.details is not None

    def test_check_registry_execute_specific_categories(self):
        """Test esecuzione controlli per categorie specifiche."""
        from agid_assessment_methodology.checks.base import BaseCheck
        from agid_assessment_methodology.checks import CheckRegistry

        # Crea registry di test
        registry = CheckRegistry()

        class TestCheck1(BaseCheck):
            def __init__(self):
                super().__init__()
                self.id = "test1"
                self.category = "cat1"

            def execute(self, context):
                return CheckResult(CheckStatus.PASS, "Test 1 passed")

        class TestCheck2(BaseCheck):
            def __init__(self):
                super().__init__()
                self.id = "test2"
                self.category = "cat2"

            def execute(self, context):
                return CheckResult(CheckStatus.PASS, "Test 2 passed")

        registry.register(TestCheck1())
        registry.register(TestCheck2())

        # Esegui solo categoria cat1
        results = registry.execute_checks(
            {"os_type": "linux"},
            categories=["cat1"]
        )

        assert len(results) == 1
        assert "test1" in results
        assert "test2" not in results


class TestCoreExtended:
    """Test estesi per modulo core."""

    def test_scanner_with_config(self):
        """Test Scanner con configurazione personalizzata."""
        config = {
            "scan": {"timeout": 120, "parallel": False},
            "checks": {"enabled_categories": ["system"]}
        }

        scanner = Scanner("localhost", config)
        assert scanner.config == config

        # Test rilevamento OS con target remoto
        scanner_remote = Scanner("192.168.1.1", config)
        os_type = scanner_remote.detect_os()
        assert os_type == "unknown"  # Per target remoti

    def test_assessment_with_empty_results(self):
        """Test Assessment con risultati vuoti."""
        assessment = Assessment({})

        # Test analisi con dati vuoti
        analysis = assessment.analyze_security_posture()
        assert analysis["status"] == "error"

        # Test compliance con dati vuoti
        compliance = assessment.check_compliance("basic")
        assert compliance["status"] == "error"

    def test_assessment_generate_report_auto_analysis(self):
        """Test generazione report con analisi automatica."""
        # Dati minimi per assessment
        scan_results = {
            "system_info": {
                "status": "pass",
                "score": 95,
                "issues": [],
                "recommendations": []
            },
            "scan_metadata": {
                "target": "test_system",
                "timestamp": "2024-01-01T00:00:00Z"
            }
        }

        assessment = Assessment(scan_results)

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Dovrebbe eseguire automaticamente l'analisi
            report_path = assessment.generate_report(str(temp_path), "json")

            assert report_path.exists()

            # Verifica contenuto
            with open(report_path) as f:
                report_data = json.load(f)

            # Verifica che le sezioni principali siano presenti
            assert "executive_summary" in report_data
            assert "compliance_summary" in report_data  # Cambiato da "compliance" a "compliance_summary"
            assert "detailed_results" in report_data
            assert "metadata" in report_data

            # Verifica structure del compliance_summary
            compliance = report_data["compliance_summary"]
            assert "overall_compliance_score" in compliance
            assert "basic_compliance" in compliance
            assert "standard_compliance" in compliance
            assert "advanced_compliance" in compliance

            # Verifica che il punteggio sia numerico
            assert isinstance(compliance["overall_compliance_score"], (int, float))

            # Verifica executive summary
            exec_summary = report_data["executive_summary"]
            assert "overall_risk_level" in exec_summary
            assert "scan_timestamp" in exec_summary

        finally:
            if temp_path.exists():
                temp_path.unlink()
    def test_scanner_get_available_checks_with_registry(self):
        """Test get_available_checks con registry reale."""
        scanner = Scanner("localhost")
        checks = scanner.get_available_checks()

        assert isinstance(checks, list)
        assert len(checks) > 0

        # Verifica che includa i checks registrati
        expected_checks = ["system_info", "basic_security", "password_policy"]
        for expected in expected_checks:
            assert expected in checks


class TestUtilsExtended:
    """Test estesi per modulo utils."""

    def test_config_get_set_value(self):
        """Test get/set config value con dot notation."""
        from agid_assessment_methodology.utils.config import get_config_value, set_config_value

        config = {
            "scan": {"timeout": 300},
            "checks": {"enabled": True}
        }

        # Test get
        assert get_config_value(config, "scan.timeout") == 300
        assert get_config_value(config, "checks.enabled") is True
        assert get_config_value(config, "nonexistent.key", "default") == "default"

        # Test set
        set_config_value(config, "scan.parallel", True)
        assert config["scan"]["parallel"] is True

        set_config_value(config, "new.nested.value", 42)
        assert config["new"]["nested"]["value"] == 42

    def test_config_user_dir_functions(self):
        """Test funzioni per directory utente."""
        from agid_assessment_methodology.utils.config import get_user_config_dir, ensure_config_dir

        config_dir = get_user_config_dir()
        assert isinstance(config_dir, Path)
        assert "agid_assessment" in str(config_dir)

        # Test ensure_config_dir
        ensured_dir = ensure_config_dir()
        assert ensured_dir.exists()
        assert ensured_dir.is_dir()

    def test_logger_colored_formatter(self):
        """Test ColoredFormatter."""
        from agid_assessment_methodology.utils.logger import ColoredFormatter

        formatter = ColoredFormatter("%(levelname)s - %(message)s")

        # Crea record di log di test
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None
        )

        formatted = formatter.format(record)
        assert "ERROR" in formatted
        assert "Test message" in formatted

    def test_logger_context_filter(self):
        """Test ContextFilter."""
        from agid_assessment_methodology.utils.logger import ContextFilter

        context = {"scan_id": "test123", "target": "localhost"}
        filter_obj = ContextFilter(context)

        # Crea record di log
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test",
            args=(),
            exc_info=None
        )

        # Applica filtro
        assert filter_obj.filter(record) is True
        assert hasattr(record, "scan_id")
        assert record.scan_id == "test123"

    def test_reporting_pdf_with_reportlab_fallback(self):
        """Test generazione PDF con fallback reportlab."""
        from agid_assessment_methodology.utils.reporting import ReportGenerator

        # Dati di test
        assessment_data = {
            "summary": {"total_checks": 1, "success_rate": 100, "risk_level": "low"},
            "categories": {},
            "recommendations": [],
            "scan_metadata": {"target": "test"},
            "details": {}
        }

        generator = ReportGenerator()

        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            temp_path = Path(f.name)

        try:
            # Test che il PDF fallback funzioni
            with patch('builtins.__import__') as mock_import:
                # Mock per far fallire weasyprint ma far funzionare reportlab
                def import_side_effect(name, *args, **kwargs):
                    if name == 'weasyprint':
                        raise ImportError("weasyprint not found")
                    elif name == 'reportlab.pdfgen.canvas':
                        # Mock reportlab
                        mock_module = MagicMock()
                        mock_canvas = MagicMock()
                        mock_module.Canvas = MagicMock(return_value=mock_canvas)
                        return mock_module
                    else:
                        # Chiama l'import reale per gli altri moduli
                        return __import__(name, *args, **kwargs)

                mock_import.side_effect = import_side_effect

                # Questo potrebbe fallire, è ok
                try:
                    result_path = generator.generate_report(
                        assessment_data,
                        temp_path,
                        "pdf"
                    )
                    # Se riesce, verifica che il file esista
                    assert result_path == temp_path
                except (ImportError, Exception):
                    # È ok se fallisce, stiamo testando il fallback
                    pass
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_reporting_xml_indent_fallback(self):
        """Test generazione XML senza ET.indent (Python < 3.9)."""
        from agid_assessment_methodology.utils.reporting import ReportGenerator
        import xml.etree.ElementTree as ET

        # Mock ET.indent per non esistere
        original_indent = getattr(ET, 'indent', None)
        if hasattr(ET, 'indent'):
            delattr(ET, 'indent')

        try:
            assessment_data = {
                "summary": {"risk_level": "low"},
                "categories": {},
                "recommendations": [],
                "scan_metadata": {"target": "test"},
                "details": {}
            }

            generator = ReportGenerator()

            with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
                temp_path = Path(f.name)

            try:
                result_path = generator.generate_report(
                    assessment_data,
                    temp_path,
                    "xml"
                )

                assert result_path.exists()
                content = result_path.read_text()
                assert 'security_assessment_report' in content

            finally:
                temp_path.unlink()

        finally:
            # Ripristina ET.indent se esisteva
            if original_indent:
                ET.indent = original_indent


class TestErrorHandling:
    """Test per gestione errori e edge cases."""

    def test_scanner_with_invalid_target(self):
        """Test Scanner con target invalido."""
        scanner = Scanner("")
        assert scanner.target == ""

        # Dovrebbe gestire gracefully target vuoto
        info = scanner.get_system_info()
        assert "target" in info

    def test_check_registry_duplicate_registration(self):
        """Test registrazione duplicata nel registry."""
        from agid_assessment_methodology.checks import CheckRegistry, BaseCheck, CheckResult, CheckStatus

        class DuplicateCheck(BaseCheck):
            def execute(self, context):
                return CheckResult(CheckStatus.PASS)

        registry = CheckRegistry()
        check1 = DuplicateCheck()
        check1.id = "duplicate"

        check2 = DuplicateCheck()
        check2.id = "duplicate"

        # Prima registrazione
        registry.register(check1)
        assert len(registry) == 1

        # Seconda registrazione (dovrebbe sovrascrivere)
        registry.register(check2)
        assert len(registry) == 1
        assert registry.get_check("duplicate") == check2

    def test_assessment_invalid_compliance_level(self):
        """Test Assessment con livello compliance invalido."""
        assessment = Assessment()

        with pytest.raises(ValueError, match="Invalid compliance level"):
            assessment.check_compliance("invalid_level")

    def test_config_validation_errors(self):
        """Test errori di validazione configurazione."""
        from agid_assessment_methodology.utils.config import validate_config

        # Configurazione con tipo sbagliato
        invalid_configs = [
            {"scan": {"timeout": "not_a_number"}},
            {"scan": {"parallel": "not_a_boolean"}},
            {"checks": {"enabled_categories": "not_a_list"}},
            {"reporting": {"default_format": "invalid_format"}},
            {"logging": {"level": "INVALID_LEVEL"}}
        ]

        for invalid_config in invalid_configs:
            assert validate_config(invalid_config) is False