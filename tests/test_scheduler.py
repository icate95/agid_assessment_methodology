import pytest
import time
from pathlib import Path
from datetime import datetime
import schedule

from agid_assessment_methodology.scheduler import AssessmentScheduler


def test_schedule_assessment():
    """Test base per la schedulazione di un assessment."""
    scheduler = AssessmentScheduler()

    # Schedula un assessment di test
    task_id = scheduler.schedule_assessment(
        target='localhost',
        frequency='daily',
        time_of_day='02:00'
    )

    # Verifica che il task sia stato aggiunto
    assert task_id in scheduler.scheduled_tasks
    assert scheduler.scheduled_tasks[task_id]['target'] == 'localhost'


def test_list_scheduled_tasks():
    """Test per l'elenco dei task schedulati."""
    scheduler = AssessmentScheduler()

    # Schedula alcuni task
    scheduler.schedule_assessment('server1', 'daily', '02:00')
    scheduler.schedule_assessment('server2', 'daily', '03:00')

    tasks = scheduler.list_scheduled_tasks()
    assert len(tasks) == 2
    assert any(task['target'] == 'server1' for task in tasks)
    assert any(task['target'] == 'server2' for task in tasks)


def test_remove_scheduled_task():
    """Test per la rimozione di un task schedulato."""
    scheduler = AssessmentScheduler()

    task_id = scheduler.schedule_assessment('testserver', 'daily', '02:00')

    # Rimuovi il task
    scheduler.remove_scheduled_task(task_id)

    # Verifica che il task sia stato rimosso
    assert task_id not in scheduler.scheduled_tasks


def test_scheduler_thread():
    """Test per l'avvio e l'arresto del thread dello scheduler."""
    scheduler = AssessmentScheduler()

    # Avvia lo scheduler
    scheduler.start()
    assert scheduler.running
    assert scheduler._scheduler_thread.is_alive()

    # Ferma lo scheduler
    scheduler.stop()
    assert not scheduler.running

    # Attendi che il thread termini
    scheduler._scheduler_thread.join(timeout=2)
    assert not scheduler._scheduler_thread.is_alive()