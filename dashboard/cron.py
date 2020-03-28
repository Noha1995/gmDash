import logging

from django_cron import CronJobBase, Schedule
from .models import MailAccount

log = logging.getLogger('django')


class AppCron(CronJobBase):
    RUN_EVERY_MINS = 1

    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = "dashboard.cron_job1"

    def do(self):
        account = MailAccount.objects.first()
        log.info("Cron started. Result: " + account.email)
        return account.email


def my_scheduled_job():
    account = MailAccount.objects.first()
    log.info("Cron 2 started. Result: " + account.email)
    return account.email