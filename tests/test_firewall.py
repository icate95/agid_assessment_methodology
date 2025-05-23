"""Test per FirewallCheck."""

import pytest
from unittest.mock import patch, MagicMock
from agid_assessment_methodology.checks.network.firewall import FirewallCheck
from agid_assessment_methodology.checks.base import CheckStatus


class TestFirewallCheck:
    """Test per la classe FirewallCheck."""

    def test_firewall_check_creation(self):
        """Test creazione FirewallCheck."""
        check = FirewallCheck()
        assert check.id == "firewall"
        assert check.name == "Firewall Configuration"
        assert check.category == "network"
        assert check.severity == "high"
        assert "windows" in check.supported_os
        assert "linux" in check.supported_os
        assert "macos" in check.supported_os

    def test_firewall_check_metadata(self):
        """Test metadati del controllo."""
        check = FirewallCheck()
        metadata = check.get_metadata()

        assert metadata["id"] == "firewall"
        assert metadata["name"] == "Firewall Configuration"
        assert metadata["category"] == "network"
        assert metadata["severity"] == "high"
        assert metadata["executed"] is False

    def test_firewall_check_applicability(self):
        """Test applicabilità del controllo."""
        check = FirewallCheck()

        assert check.is_applicable({"os_type": "windows"}) is True
        assert check.is_applicable({"os_type": "linux"}) is True
        assert check.is_applicable({"os_type": "darwin"}) is True
        assert check.is_applicable({"os_type": "unknown"}) is False

    @patch('subprocess.run')
    def test_windows_firewall_enabled(self, mock_subprocess):
        """Test Windows firewall abilitato."""
        check = FirewallCheck()

        # Mock della risposta di netsh per firewall abilitato
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
        """
        mock_subprocess.return_value = mock_result

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert "enabled on all profiles" in result.message
        assert result.details["status"] == "enabled"

    @patch('subprocess.run')
    def test_windows_firewall_partially_enabled(self, mock_subprocess):
        """Test Windows firewall parzialmente abilitato."""
        check = FirewallCheck()

        # Mock della risposta con un profilo disabilitato
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
        """
        mock_subprocess.return_value = mock_result

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.WARNING
        assert "not enabled on all profiles" in result.message
        assert result.details["status"] == "partially_enabled"

    @patch('subprocess.run')
    def test_linux_ufw_active(self, mock_subprocess):
        """Test Linux UFW attivo."""
        check = FirewallCheck()

        # Mock per UFW status
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
        """
        mock_subprocess.return_value = mock_result

        context = {"os_type": "linux"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert "active and configured" in result.message
        assert result.details["firewall_type"] == "ufw"
        assert result.details["status"] == "active"

    @patch('subprocess.run')
    def test_linux_ufw_inactive(self, mock_subprocess):
        """Test Linux UFW inattivo."""
        check = FirewallCheck()

        # Mock per UFW status inattivo
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Status: inactive"
        mock_subprocess.return_value = mock_result

        context = {"os_type": "linux"}
        result = check.execute(context)

        assert result.status == CheckStatus.FAIL
        assert "installed but inactive" in result.message
        assert result.details["firewall_type"] == "ufw"
        assert result.details["status"] == "inactive"

    @patch('subprocess.run')
    def test_linux_no_firewall(self, mock_subprocess):
        """Test Linux senza firewall."""
        check = FirewallCheck()

        # Mock per tutti i comandi che falliscono (nessun firewall)
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_subprocess.return_value = mock_result

        context = {"os_type": "linux"}
        result = check.execute(context)

        assert result.status == CheckStatus.FAIL
        assert "No firewall detected" in result.message
        assert result.details["firewall_type"] is None

    @patch('subprocess.run')
    def test_macos_firewall_enabled(self, mock_subprocess):
        """Test macOS firewall abilitato."""
        check = FirewallCheck()

        # Mock per macOS firewall abilitato
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is enabled. (State = 1)"
        mock_subprocess.return_value = mock_result

        context = {"os_type": "darwin"}
        result = check.execute(context)

        assert result.status == CheckStatus.PASS
        assert "enabled" in result.message
        assert result.details["application_firewall"] is True

    @patch('subprocess.run')
    def test_macos_firewall_disabled(self, mock_subprocess):
        """Test macOS firewall disabilitato."""
        check = FirewallCheck()

        # Mock per macOS firewall disabilitato
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Firewall is disabled. (State = 0)"
        mock_subprocess.return_value = mock_result

        context = {"os_type": "darwin"}
        result = check.execute(context)

        assert result.status == CheckStatus.FAIL
        assert "disabled" in result.message
        assert result.details["application_firewall"] is False

    def test_unsupported_os(self):
        """Test OS non supportato."""
        check = FirewallCheck()

        context = {"os_type": "freebsd"}
        result = check.execute(context)

        assert result.status == CheckStatus.ERROR
        assert "Unsupported OS" in result.message

    @patch('subprocess.run')
    def test_subprocess_error(self, mock_subprocess):
        """Test errore subprocess."""
        check = FirewallCheck()

        # Mock per errore subprocess
        mock_subprocess.side_effect = Exception("Command failed")

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.ERROR
        assert "Command failed" in result.message

    @patch('subprocess.run')
    def test_windows_parse_profiles(self, mock_subprocess):
        """Test parsing dei profili Windows."""
        check = FirewallCheck()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
Inbound Rules                         Rules are configured

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       AllowInbound,AllowOutbound
        """
        mock_subprocess.return_value = mock_result

        # Test del metodo interno di parsing
        profiles = check._parse_windows_firewall_profiles(mock_result.stdout)

        assert "Domain Profile Settings" in profiles
        assert "Private Profile Settings" in profiles
        assert profiles["Domain Profile Settings"]["State"] == "ON"
        assert profiles["Private Profile Settings"]["State"] == "OFF"

    def test_recommendations_generation(self):
        """Test generazione raccomandazioni."""
        check = FirewallCheck()

        # Test raccomandazioni Windows
        windows_results = {
            "status": "partially_enabled",
            "profiles": {
                "Domain Profile": {"State": "ON"},
                "Private Profile": {"State": "OFF"}
            }
        }

        recommendations = check._get_windows_firewall_recommendations(windows_results)
        assert len(recommendations) > 0
        assert any("Enable firewall for Private Profile" in rec for rec in recommendations)

        # Test raccomandazioni Linux
        linux_results = {
            "firewall_type": "ufw",
            "status": "inactive"
        }

        recommendations = check._get_linux_firewall_recommendations(linux_results)
        assert len(recommendations) > 0
        assert any("sudo ufw enable" in rec for rec in recommendations)

    @patch('subprocess.run')
    def test_timeout_handling(self, mock_subprocess):
        """Test gestione timeout."""
        check = FirewallCheck()

        # Mock per timeout
        mock_subprocess.side_effect = subprocess.TimeoutExpired("netsh", 30)

        context = {"os_type": "windows"}
        result = check.execute(context)

        assert result.status == CheckStatus.ERROR
        assert result.details["status"] == "timeout"

    def test_run_with_context(self):
        """Test esecuzione completa con contesto."""
        check = FirewallCheck()

        # Test che il controllo sia applicabile
        context = {"os_type": "linux"}
        assert check.is_applicable(context) is True

        # Test esecuzione (con mock per evitare chiamate reali)
        with patch.object(check, 'execute') as mock_execute:
            mock_execute.return_value = MagicMock(status=CheckStatus.PASS)

            result = check.run(context)
            assert result.status == CheckStatus.PASS
            assert check._executed is True