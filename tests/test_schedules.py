"""schedules.py: cron expressions and the scheduler's choice of due schedules."""
from datetime import datetime, timezone

import pytest

from asma import schedules, validation
from conftest import add_target

MONDAY_3AM = datetime(2026, 11, 16, 3, 0, tzinfo=timezone.utc)


def test_parse_cron():
    assert schedules.parse_cron("*/20 1-5/2 * * 0") == [
        {0, 20, 40},          # minute
        {1, 3, 5},            # hour
        set(range(1, 32)),    # day of month
        set(range(1, 13)),    # month
        {0},                  # day of week (Sunday)
    ]
    # 4 fields ; minutes range 0-59 ; weekday range 0-6
    for bad in ("0 3 * *", "60 * * * *", "0 3 * * 7"):
        with pytest.raises(validation.InputError):
            schedules.parse_cron(bad)


def test_day_of_month_or_day_of_week():
    """As in cron: with both restricted, either one matching is enough."""
    assert schedules.cron_matches("0 3 1 * 1", MONDAY_3AM)      # Monday, the 16th
    assert not schedules.cron_matches("0 3 1 * *", MONDAY_3AM)  # only the 1st


def test_due_schedule_starts_one_job(app, db):
    app.config["HIBS_API_KEY"] = "test-key"
    app.extensions["asma_queues"]["hibs"].submit = lambda *args: None  # never run
    db.execute("INSERT INTO schedules (target_id, scanner, cron, created_by_user_id, "
               "created_at, updated_at) VALUES (?, 'hibs', '0 3 * * *', 1, '', '')",
               (add_target(db),))
    schedules.queue_due(app, MONDAY_3AM)
    schedules.queue_due(app, MONDAY_3AM)  # same minute again: nothing new
    assert db.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1
