"""Test per AntivirusCheck."""

import pytest
import json
from unittest.mock import patch, MagicMock
from agid_assessment_methodology.checks.malware.antivirus import AntivirusCheck
from agid_assessment_methodology.checks.base import CheckStatus


class TestAntivirusCheck:
    """Test per la classe AntivirusCheck."""

    def test_antivirus_check_creation(self):
        """Test creazione AntivirusCheck."""
        check = AntivirusCheck()
        assert check.id == "antivirus"
        assert check.name == "Antivirus Protection"
        assert check.category == "malware"
        assert check.severity == "critical"
        # high
        assert "windows" in check.supported_os
        assert "linux" in check.supported_os
        assert "macos" in check.supported_os

    def test_antivirus_check_metadata(self):
        """Test metadati del controllo."""
        check = AntivirusCheck()
        metadata = check.get_metadata()

        assert metadata["id"] == "antivirus"
        assert metadata["name"] == "Antivirus Protection"
        assert metadata["category"] == "malware"
        assert metadata["severity"] == "critical"
        # high

    @patch('subprocess.run')
    def test_windows_defender_enabled(self, mock_subprocess):
        """Test Windows Defender abilitato."""
        check = AntivirusCheck()

        # Mock della risposta PowerShell per Defender abilitato
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "AntivirusEnabled": True,
            "AntiSpywareEnabled": True,
            "RealTimeProtectionEnabled": True,
            "OnAccessProtectionEnabled": True,
            "BehaviorMonitorEnabled": True,
            "EngineVersion": "1.1.19300.2"
        })
        mock_subprocess.return_value = mock_result

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert "active" in result.message
        assert result.details["defender_status"] == "enabled"
        assert result.details["real_time_protection"] is True

    @patch('subprocess.run')
    def test_windows_defender_disabled(self, mock_subprocess):
        """Test Windows Defender disabilitato."""
        check = AntivirusCheck()

        # Mock per Defender disabilitato
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "AntivirusEnabled": False,
            "RealTimeProtectionEnabled": False
        })
        mock_subprocess.return_value = mock_result

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.FAIL
        assert result.details["defender_status"] == "disabled"
        assert result.details["real_time_protection"] is False

    @patch('subprocess.run')
    def test_windows_third_party_antivirus(self, mock_subprocess):
        """Test antivirus di terze parti su Windows."""
        check = AntivirusCheck()

        # Prima chiamata: Defender disabilitato
        # Seconda chiamata: WMI per antivirus di terze parti
        mock_results = [
            # Defender status
            MagicMock(returncode=0, stdout=json.dumps({"AntivirusEnabled": False})),
            # WMI AntiVirusProduct
            MagicMock(returncode=0, stdout=json.dumps([{
                "displayName": "Norton Security",
                "productState": "0x1000",  # Enabled
                "pathToSignedProductExe": "C:\\Program Files\\Norton\\Norton.exe"
            }]))
        ]
        mock_subprocess.side_effect = mock_results

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert len(result.details["third_party_av"]) > 0
        assert result.details["third_party_av"][0]["name"] == "Norton Security"
        assert result.details["third_party_av"][0]["status"] == "active"

    @patch('subprocess.run')
    def test_linux_clamav_running(self, mock_subprocess):
        """Test ClamAV attivo su Linux."""
        check = AntivirusCheck()

        # Mock per which clamscan (installato)
        # Mock per systemctl is-active (attivo)
        mock_results = [
            MagicMock(returncode=0, stdout="/usr/bin/clamscan"),  # which clamscan
            MagicMock(returncode=0, stdout="active")  # systemctl is-active
        ]
        mock_subprocess.side_effect = mock_results

        context = {"os_type": "linux"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert result.details["clamav_installed"] is True
        assert result.details["clamav_running"] is True

    @patch('subprocess.run')
    def test_linux_clamav_installed_not_running(self, mock_subprocess):
        """Test ClamAV installato ma non attivo."""
        check = AntivirusCheck()

        # Mock per which clamscan (installato) ma systemctl failed
        mock_results = [
            MagicMock(returncode=0, stdout="/usr/bin/clamscan"),  # which clamscan
            MagicMock(returncode=1, stdout="inactive")  # systemctl is-active
        ]
        mock_subprocess.side_effect = mock_results

        context = {"os_type": "linux"}
        result = check.execute(context)

        assert result.status == CheckStatus.WARNING
        assert result.details["clamav_installed"] is True
        assert result.details["clamav_running"] is False

    @patch('subprocess.run')
    def test_linux_no_antivirus(self, mock_subprocess):
        """Test Linux senza antivirus."""
        check = AntivirusCheck()

        # Mock per which che fallisce (non installato)
        mock_subprocess.return_value = MagicMock(returncode=1)

        context = {"os_type": "linux"}
        result = check.execute(context)

        assert result.status == CheckStatus.FAIL
        assert result.details["clamav_installed"] is False

    @patch('subprocess.run')
    def test_macos_xprotect_active(self, mock_subprocess):
        """Test XProtect attivo su macOS."""
        check = AntivirusCheck()

        # Mock per ps aux che mostra XProtect
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="user  1234  XProtectService"
        )

        context = {"os_type": "darwin"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert result.details["xprotect_enabled"] is True

    @patch('subprocess.run')
    def test_macos_gatekeeper_enabled(self, mock_subprocess):
        """Test Gatekeeper abilitato su macOS."""
        check = AntivirusCheck()

        # Mock per spctl --status
        mock_results = [
            MagicMock(returncode=0, stdout="No XProtect found"),  # ps aux
            MagicMock(returncode=0, stdout="assessments enabled")  # spctl --status
        ]
        mock_subprocess.side_effect = mock_results

        context = {"os_type": "darwin"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert result.details["gatekeeper_enabled"] is True

    def test_unsupported_os(self):
        """Test OS non supportato."""
        check = AntivirusCheck()

        context = {"os_type": "freebsd"}
        result = check.execute(context)

        assert result.status == CheckStatus.ERROR
        assert "Unsupported OS" in result.message

    @patch('subprocess.run')
    def test_subprocess_error(self, mock_subprocess):
        """Test errore subprocess."""
        check = AntivirusCheck()

        # Mock per errore subprocess
        mock_subprocess.side_effect = Exception("Command failed")

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.ERROR
        assert "Command failed" in result.message

    def test_recommendations_generation(self):
        """Test generazione raccomandazioni."""
        check = AntivirusCheck()

        # Test raccomandazioni Windows senza antivirus
        windows_results = {
            "defender_status": "disabled",
            "third_party_av": [],
            "real_time_protection": False
        }

        recommendations = check._get_windows_recommendations(windows_results)
        assert len(recommendations) > 0
        assert any("Install and enable" in rec for rec in recommendations)

        # Test raccomandazioni Linux
        linux_results = {
            "clamav_installed": False,
            "other_av": []
        }

        recommendations = check._get_linux_recommendations(linux_results)
        assert len(recommendations) > 0
        assert any("installing ClamAV" in rec for rec in recommendations)

    @patch('subprocess.run')
    def test_windows_process_name_extraction(self, mock_subprocess):
        """Test estrazione nome processo Windows."""
        check = AntivirusCheck()

        # Mock per Get-Process
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"ProcessName": "MsMpEng"})
        )

        process_name = check._get_windows_process_name("1234")
        assert process_name == "MsMpEng"

    @patch('subprocess.run')
    def test_linux_process_check_with_lsof(self, mock_subprocess):
        """Test controllo processo Linux con lsof."""
        check = AntivirusCheck()

        # Mock per lsof
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="clamd    1234 clamav    3u  IPv4 12345      0t0  TCP *:3310 (LISTEN)"
        )

        process_info = check._get_linux_process_for_port(3310, "tcp")
        assert process_info["name"] == "clamd"
        assert process_info["pid"] == "1234"

    def test_product_state_decoding(self):
        """Test decodifica product state Windows."""
        check = AntivirusCheck()

        # Test stati comuni
        # 0x1000 = enabled
        # 0x10 = updated

        # Stato: enabled e updated
        state = 0x1010
        enabled = bool(state & 0x1000)
        updated = bool(state & 0x10)

        assert enabled is True
        assert updated is True

        # Stato: enabled ma non updated
        state = 0x1000
        enabled = bool(state & 0x1000)
        updated = bool(state & 0x10)

        assert enabled is True
        assert updated is False

    @patch('subprocess.run')
    def test_timeout_handling(self, mock_subprocess):
        """Test gestione timeout."""
        check = AntivirusCheck()

        # Mock per timeout
        mock_subprocess.side_effect = subprocess.TimeoutExpired("powershell", 30)

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.ERROR

    def test_run_with_context(self):
        """Test esecuzione completa con contesto."""
        check = AntivirusCheck()

        # Test che il controllo sia applicabile
        context = {"os_type": "windows"}
        assert check.is_applicable(context) is True

        # Test esecuzione (con mock per evitare chiamate reali)
        with patch.object(check, 'execute') as mock_execute:
            mock_execute.return_value = MagicMock(status=CheckStatus.PASS)

            result = check.run(context)
            assert result.status == CheckStatus.PASS
            assert check._executed is True