"""Test per il modulo checks."""

import pytest
from agid_assessment_methodology.checks import (
    BaseCheck, CheckResult, CheckStatus, CheckRegistry,
    SystemInfoCheck, BasicSecurityCheck, PasswordPolicyCheck
)


class MockCheck(BaseCheck):
    """Check mock per test."""

    def __init__(self, check_id="mock", status=CheckStatus.PASS):
        super().__init__()
        self.id = check_id
        self.name = f"Mock Check {check_id}"
        self.category = "test"
        self._mock_status = status

    def execute(self, context):
        return CheckResult(
            status=self._mock_status,
            message=f"Mock check {self.id} executed"
        )


class TestCheckResult:
    """Test per CheckResult."""

    def test_check_result_creation(self):
        """Test creazione CheckResult."""
        result = CheckResult(
            status=CheckStatus.PASS,
            message="Test passed",
            score=95.0
        )

        assert result.status == CheckStatus.PASS
        assert result.message == "Test passed"
        assert result.score == 95.0
        assert result.details == {}
        assert result.issues == []
        assert result.recommendations == []
        assert result.timestamp is not None

    def test_add_issue(self):
        """Test aggiunta issue."""
        result = CheckResult(CheckStatus.FAIL)

        issue = {"severity": "high", "description": "Test issue"}
        result.add_issue(issue)

        assert len(result.issues) == 1
        assert result.issues[0] == issue

    def test_add_recommendation(self):
        """Test aggiunta recommendation."""
        result = CheckResult(CheckStatus.WARNING)

        result.add_recommendation("Fix this issue")

        assert len(result.recommendations) == 1
        assert result.recommendations[0] == "Fix this issue"

    def test_to_dict(self):
        """Test conversione a dizionario."""
        result = CheckResult(
            status=CheckStatus.PASS,
            message="Test",
            score=85.0
        )

        result_dict = result.to_dict()

        assert result_dict["status"] == "pass"
        assert result_dict["message"] == "Test"
        assert result_dict["score"] == 85.0
        assert "timestamp" in result_dict


class TestBaseCheck:
    """Test per BaseCheck."""

    def test_check_metadata(self):
        """Test metadati check."""
        check = MockCheck("test_check")
        metadata = check.get_metadata()

        assert metadata["id"] == "test_check"
        assert metadata["name"] == "Mock Check test_check"
        assert metadata["category"] == "test"
        assert metadata["executed"] is False

    def test_is_applicable(self):
        """Test applicabilità check."""
        check = MockCheck()
        check.supported_os = ["linux", "windows"]

        assert check.is_applicable({"os_type": "linux"}) is True
        assert check.is_applicable({"os_type": "windows"}) is True
        assert check.is_applicable({"os_type": "macos"}) is False
        assert check.is_applicable({"os_type": "unknown"}) is False

    def test_run_success(self):
        """Test esecuzione check con successo."""
        check = MockCheck("success", CheckStatus.PASS)
        context = {"os_type": "linux"}

        result = check.run(context)

        assert result.status == CheckStatus.PASS
        assert check._executed is True
        assert check._last_result is not None

    def test_run_skipped(self):
        """Test esecuzione check skippato."""
        check = MockCheck()
        check.supported_os = ["windows"]
        context = {"os_type": "linux"}

        result = check.run(context)

        assert result.status == CheckStatus.SKIPPED
        assert "not applicable" in result.message

    def test_run_error(self):
        """Test esecuzione check con errore."""

        class ErrorCheck(BaseCheck):
            def execute(self, context):
                raise ValueError("Test error")

        check = ErrorCheck()
        result = check.run({"os_type": "linux"})

        assert result.status == CheckStatus.ERROR
        assert "Test error" in result.message


class TestCheckRegistry:
    """Test per CheckRegistry."""

    def test_registry_creation(self):
        """Test creazione registry."""
        registry = CheckRegistry()
        assert len(registry) == 0
        assert registry.get_categories() == []

    def test_register_check(self):
        """Test registrazione check."""
        registry = CheckRegistry()
        check = MockCheck("reg_test")

        registry.register(check)

        assert len(registry) == 1
        assert registry.get_check("reg_test") == check
        assert "test" in registry.get_categories()

    def test_get_checks_by_category(self):
        """Test ottenimento checks per categoria."""
        registry = CheckRegistry()
        check1 = MockCheck("check1")
        check2 = MockCheck("check2")
        check1.category = "cat1"
        check2.category = "cat2"

        registry.register(check1)
        registry.register(check2)

        cat1_checks = registry.get_checks_by_category("cat1")
        assert len(cat1_checks) == 1
        assert cat1_checks[0] == check1

    def test_get_checks_for_os(self):
        """Test ottenimento checks per OS."""
        registry = CheckRegistry()
        check1 = MockCheck("os_check1")
        check2 = MockCheck("os_check2")
        check1.supported_os = ["linux"]
        check2.supported_os = ["windows", "linux"]

        registry.register(check1)
        registry.register(check2)

        linux_checks = registry.get_checks_for_os("linux")
        windows_checks = registry.get_checks_for_os("windows")

        assert len(linux_checks) == 2
        assert len(windows_checks) == 1
        assert check2 in windows_checks

    def test_execute_checks(self):
        """Test esecuzione checks."""
        registry = CheckRegistry()
        check1 = MockCheck("exec1", CheckStatus.PASS)
        check2 = MockCheck("exec2", CheckStatus.FAIL)

        registry.register(check1)
        registry.register(check2)

        results = registry.execute_checks({"os_type": "linux"})

        assert len(results) == 2
        assert "exec1" in results
        assert "exec2" in results
        assert results["exec1"].status == CheckStatus.PASS
        assert results["exec2"].status == CheckStatus.FAIL

    def test_execute_specific_checks(self):
        """Test esecuzione checks specifici."""
        registry = CheckRegistry()
        check1 = MockCheck("spec1")
        check2 = MockCheck("spec2")

        registry.register(check1)
        registry.register(check2)

        results = registry.execute_checks(
            {"os_type": "linux"},
            check_ids=["spec1"]
        )

        assert len(results) == 1
        assert "spec1" in results
        assert "spec2" not in results

    def test_registry_info(self):
        """Test informazioni registry."""
        registry = CheckRegistry()
        check1 = MockCheck("info1")
        check2 = MockCheck("info2")
        check1.category = "cat1"
        check2.category = "cat1"

        registry.register(check1)
        registry.register(check2)

        info = registry.get_registry_info()

        assert info["total_checks"] == 2
        assert info["categories"]["cat1"] == 2
        assert len(info["available_checks"]) == 2


class TestSystemInfoCheck:
    """Test per SystemInfoCheck."""

    def test_system_info_check_creation(self):
        """Test creazione SystemInfoCheck."""
        check = SystemInfoCheck()
        assert check.id == "system_info"
        assert check.category == "system"
        assert check.severity == "low"
        assert "windows" in check.supported_os
        assert "linux" in check.supported_os

    def test_system_info_execution(self):
        """Test esecuzione SystemInfoCheck."""
        check = SystemInfoCheck()
        context = {"os_type": "linux"}

        result = check.run(context)

        assert result.status in [CheckStatus.PASS, CheckStatus.ERROR]
        if result.status == CheckStatus.PASS:
            assert "hostname" in result.details
            assert result.score is not None


class TestBasicSecurityCheck:
    """Test per BasicSecurityCheck."""

    def test_basic_security_check_creation(self):
        """Test creazione BasicSecurityCheck."""
        check = BasicSecurityCheck()
        assert check.id == "basic_security"
        assert check.category == "system"
        assert check.severity == "medium"

    def test_basic_security_execution(self):
        """Test esecuzione BasicSecurityCheck."""
        check = BasicSecurityCheck()
        context = {"os_type": "linux"}

        result = check.run(context)

        assert result.status in [CheckStatus.PASS, CheckStatus.WARNING, CheckStatus.FAIL, CheckStatus.ERROR]
        assert result.details is not None


class TestPasswordPolicyCheck:
    """Test per PasswordPolicyCheck."""

    def test_password_policy_check_creation(self):
        """Test creazione PasswordPolicyCheck."""
        check = PasswordPolicyCheck()
        assert check.id == "password_policy"
        assert check.category == "authentication"
        assert check.severity == "high"

    def test_password_policy_skipped_unknown_os(self):
        """Test PasswordPolicyCheck skippato per OS sconosciuto."""
        check = PasswordPolicyCheck()
        context = {"os_type": "unknown"}

        result = check.run(context)

        assert result.status == CheckStatus.SKIPPED