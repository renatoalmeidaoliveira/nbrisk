"""
NetBox background jobs for nb_risk.

Registers SyncKEVJob and SyncEPSSJob as system jobs using NetBox's
JobRunner framework. These run automatically on the configured interval
via the NetBox-RQ worker — no management commands or cron required.

Both jobs are also manually triggerable from the Risk Assessment menu
(CVE Integration → Sync Jobs).
"""

from core.choices import JobIntervalChoices
from netbox.jobs import JobRunner, system_job

__all__ = (
    'SyncKEVJob',
    'SyncEPSSJob',
)


@system_job(interval=JobIntervalChoices.INTERVAL_DAILY)
class SyncKEVJob(JobRunner):
    """
    Sync the CISA Known Exploited Vulnerabilities catalog against all
    Vulnerability records that have a CVE ID. Runs daily automatically.
    Can also be triggered manually from the UI.
    """

    class Meta:
        name = 'Sync CISA KEV Catalog'

    def run(self, *args, **kwargs):
        from .kev import sync_kev_to_db

        self.logger.info("Starting CISA KEV catalog sync...")
        updated, cleared, total = sync_kev_to_db()
        self.logger.info(
            f"KEV sync complete: {updated} vulnerabilities updated, "
            f"{cleared} flags cleared, {total} total entries in catalog."
        )


@system_job(interval=JobIntervalChoices.INTERVAL_DAILY)
class SyncEPSSJob(JobRunner):
    """
    Sync EPSS (Exploit Prediction Scoring System) scores from FIRST.org
    for all Vulnerability records that have a CVE ID. Runs daily automatically.
    Can also be triggered manually from the UI.
    """

    class Meta:
        name = 'Sync EPSS Scores'

    def run(self, *args, **kwargs):
        from .epss import sync_epss_to_db

        self.logger.info("Starting EPSS score sync...")
        updated, total = sync_epss_to_db()
        self.logger.info(
            f"EPSS sync complete: {updated}/{total} vulnerabilities updated."
        )
