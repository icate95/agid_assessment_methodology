"""Controllo per la raccolta di informazioni di sistema."""

import platform
import psutil
from typing import Dict, Any
from agid_assessment_methodology.checks.base import BaseCheck, CheckResult, CheckStatus



class SystemInfoCheck(BaseCheck):
    """Controllo per raccogliere informazioni di base sul sistema."""

    def __init__(self):
        super().__init__()
        self.id = "system_info"
        self.name = "System Information"
        self.description = "Raccoglie informazioni di base sul sistema operativo e hardware"
        self.category = "system"
        self.severity = "low"
        self.supported_os = ["windows", "linux", "macos"]

    def execute(self, context: Dict[str, Any]) -> CheckResult:
        """
        Esegue la raccolta di informazioni di sistema.

        Args:
            context: Contesto di esecuzione

        Returns:
            Risultato del controllo con informazioni di sistema
        """
        try:
            # Raccoglie informazioni base
            system_info = {
                "hostname": platform.node(),
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture(),
                "python_version": platform.python_version(),
            }

            # Aggiunge informazioni su memoria e CPU se psutil disponibile
            try:
                import psutil

                # Informazioni memoria
                memory = psutil.virtual_memory()
                system_info["memory"] = {
                    "total": memory.total,
                    "available": memory.available,
                    "percent_used": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                }

                # Informazioni CPU
                system_info["cpu"] = {
                    "physical_cores": psutil.cpu_count(logical=False),
                    "logical_cores": psutil.cpu_count(logical=True),
                    "current_frequency": psutil.cpu_freq().current if psutil.cpu_freq() else None,
                    "usage_percent": psutil.cpu_percent(interval=1)
                }

                # Informazioni disco
                disk_usage = psutil.disk_usage('/')
                system_info["disk"] = {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free,
                    "percent_used": (disk_usage.used / disk_usage.total) * 100
                }

            except ImportError:
                self._logger.warning("psutil not available, skipping extended system info")

            # Determina lo score basato sulla completezza delle informazioni
            info_completeness = len([v for v in system_info.values() if v is not None and v != ""])
            total_fields = len(system_info)
            score = (info_completeness / total_fields) * 100

            return CheckResult(
                status=CheckStatus.PASS,
                message=f"Successfully collected system information for {system_info.get('hostname', 'unknown')}",
                details=system_info,
                score=score
            )

        except Exception as e:
            return CheckResult(
                status=CheckStatus.ERROR,
                message=f"Failed to collect system information: {str(e)}",
                details={"error": str(e)}
            )