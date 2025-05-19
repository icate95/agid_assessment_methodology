"""Test per il modulo CLI."""

import pytest
from typer.testing import CliRunner

from agid_assessment_methodology.cli.main import app


class TestCLI:
    """Test per i comandi CLI di base."""

    def setup_method(self):
        """Setup per ogni test."""
        self.runner = CliRunner()

    def test_version_command(self):
        """Test del comando version."""
        result = self.runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "AGID Assessment Methodology" in result.stdout

    def test_info_command(self):
        """Test del comando info."""
        result = self.runner.invoke(app, ["info"])
        assert result.exit_code == 0
        # Cambiamo il test per verificare che ci siano le informazioni di sistema
        assert "System Information" in result.stdout
        assert "Platform" in result.stdout
        assert "Python Version" in result.stdout
        assert "Tool Version" in result.stdout

    def test_help_command(self):
        """Test del comando help."""
        result = self.runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "agid-assessment" in result.stdout