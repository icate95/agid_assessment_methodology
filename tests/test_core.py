"""Test per il modulo core."""

import pytest
from agid_assessment_methodology.core import Scanner, Assessment


class TestScanner:
    """Test per la classe Scanner."""

    def test_scanner_creation(self):
        """Test creazione scanner."""
        scanner = Scanner("localhost")
        assert scanner.target == "localhost"
        assert scanner.config == {}

    def test_local_target_detection(self):
        """Test rilevamento target locale."""
        # Test target locali
        local_targets = ["localhost", "127.0.0.1", "::1", "."]
        for target in local_targets:
            scanner = Scanner(target)
            assert scanner._is_local is True

        # Test target remoto
        scanner = Scanner("192.168.1.100")
        assert scanner._is_local is False

    def test_os_detection(self):
        """Test rilevamento OS."""
        scanner = Scanner("localhost")
        os_type = scanner.detect_os()
        assert os_type in ["windows", "linux", "macos", "unknown"]
        assert scanner.os_type == os_type

    def test_system_info_collection(self):
        """Test raccolta informazioni sistema."""
        scanner = Scanner("localhost")
        info = scanner.get_system_info()

        assert "target" in info
        assert "is_local" in info
        assert "os_type" in info
        assert info["target"] == "localhost"

    def test_available_checks(self):
        """Test controlli disponibili."""
        scanner = Scanner("localhost")
        checks = scanner.get_available_checks()

        assert isinstance(checks, list)
        assert len(checks) > 0
        assert "system_info" in checks
        assert "basic_security" in checks

    def test_basic_scan(self):
        """Test scansione base."""
        scanner = Scanner("localhost")
        results = scanner.run_basic_scan()

        assert isinstance(results, dict)
        assert "system_info" in results
        assert "basic_security" in results
        assert "scan_metadata" in results

        # Verifica struttura dei risultati
        assert results["system_info"]["status"] == "pass"
        assert results["basic_security"]["status"] == "pass"


class TestAssessment:
    """Test per la classe Assessment."""

    def test_assessment_creation(self):
        """Test creazione assessment."""
        assessment = Assessment()
        assert assessment.scan_results == {}
        assert assessment.assessment_results == {}

    def test_load_scan_results(self):
        """Test caricamento risultati scansione."""
        assessment = Assessment()
        test_results = {"test": "data"}
        assessment.load_scan_results(test_results)
        assert assessment.scan_results == test_results

    def test_compliance_check_invalid_level(self):
        """Test controllo compliance con livello invalido."""
        assessment = Assessment()
        with pytest.raises(ValueError):
            assessment.check_compliance("invalid_level")

    def test_compliance_check_no_results(self):
        """Test controllo compliance senza risultati."""
        assessment = Assessment()
        result = assessment.check_compliance("basic")
        assert result["status"] == "error"

    def test_security_posture_analysis_no_results(self):
        """Test analisi sicurezza senza risultati."""
        assessment = Assessment()
        result = assessment.analyze_security_posture()
        assert result["status"] == "error"

    def test_full_workflow(self):
        """Test workflow completo scanner + assessment."""
        # Crea scanner ed esegui scansione
        scanner = Scanner("localhost")
        scan_results = scanner.run_basic_scan()

        # Crea assessment e analizza
        assessment = Assessment(scan_results)
        analysis = assessment.analyze_security_posture()

        # Verifica risultati analisi
        assert "summary" in analysis
        assert "categories" in analysis
        assert "recommendations" in analysis

        # Verifica compliance
        compliance = assessment.check_compliance("basic")
        assert "level" in compliance
        assert "status" in compliance
        assert "compliance_percentage" in compliance

        # Verifica report summary
        summary = assessment.generate_report_summary()
        assert "assessment_timestamp" in summary
        assert "overall_status" in summary
        assert "compliance" in summary