# src/agid_assessment_methodology/scheduler.py
import logging
import platform
import schedule
import time
import threading
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime

from .core.scanner import Scanner
from .core.assessment import Assessment
from .utils.reporting import ReportGenerator

logger = logging.getLogger(__name__)


class AssessmentScheduler:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Inizializza lo scheduler per gli assessment.

        Args:
            config: Configurazione per lo scheduler
        """
        self.config = config or {}
        self.scheduled_tasks = {}
        self.running = False
        self._scheduler_thread = None

    def schedule_assessment(
            self,
            target: str,
            frequency: str = 'daily',
            time_of_day: str = '02:00',
            categories: Optional[List[str]] = None,
            output_dir: Optional[str] = None
    ) -> str:
        """
        Programma un assessment ricorrente.

        Args:
            target: Sistema da analizzare
            frequency: Frequenza ('daily', 'weekly', 'monthly')
            time_of_day: Ora del giorno per l'assessment
            categories: Categorie di controlli da eseguire
            output_dir: Directory per i report

        Returns:
            ID del task schedulato
        """
        task_id = f"{target}_{frequency}"

        def assessment_job():
            logger.info(f"Running scheduled assessment for {target}")
            scanner = Scanner(target, self.config)

            # Esegui scan con categorie specificate
            scan_results = scanner.scan(enabled_categories=categories)

            # Crea assessment
            assessment = Assessment(scan_results)
            analysis = assessment.analyze_security_posture()

            # Genera report
            if not output_dir:
                output_dir = self.config.get('reporting', {}).get('output_directory', 'reports')

            report_name = f"assessment_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            report_path = Path(output_dir) / report_name

            generator = ReportGenerator()
            generator.generate_report(
                analysis,
                report_path,
                format_type='html',
                include_raw_data=True
            )

            logger.info(f"Assessment report generated: {report_path}")

        # Configura la schedulazione basata sulla frequenza
        if frequency == 'daily':
            schedule.every().day.at(time_of_day).do(assessment_job)
        elif frequency == 'weekly':
            schedule.every().week.at(time_of_day).do(assessment_job)
        elif frequency == 'monthly':
            schedule.every(30).days.at(time_of_day).do(assessment_job)
        else:
            raise ValueError(f"Invalid frequency: {frequency}")

        self.scheduled_tasks[task_id] = {
            'target': target,
            'frequency': frequency,
            'time': time_of_day,
            'categories': categories,
            'job': assessment_job
        }

        return task_id

    def start(self):
        """Avvia lo scheduler in un thread separato."""
        if not self.running:
            self.running = True
            self._scheduler_thread = threading.Thread(target=self._run_scheduler)
            self._scheduler_thread.daemon = True
            self._scheduler_thread.start()
            logger.info("Assessment scheduler started")

    def stop(self):
        """Ferma lo scheduler."""
        self.running = False
        if self._scheduler_thread:
            self._scheduler_thread.join()
        logger.info("Assessment scheduler stopped")

    def _run_scheduler(self):
        """Thread interno per l'esecuzione dello scheduler."""
        while self.running:
            schedule.run_pending()
            time.sleep(1)

    def list_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Elenca i task schedulati."""
        return list(self.scheduled_tasks.values())

    def remove_scheduled_task(self, task_id: str):
        """Rimuove un task schedulato."""
        if task_id in self.scheduled_tasks:
            job = self.scheduled_tasks[task_id]['job']
            schedule.cancel_job(job)
            del self.scheduled_tasks[task_id]