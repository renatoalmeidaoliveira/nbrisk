"""
Management command wrapper for SyncKEVJob.

Prefer triggering via the NetBox UI (Risk Assessment → CVE Integration →
Sync Jobs) or the background job scheduler. This command is retained for
environments where direct CLI access is available (bare-metal, dev).
"""

from django.core.management.base import BaseCommand
from nb_risk.kev import fetch_kev_catalog, sync_kev_to_db


class Command(BaseCommand):
    help = (
        "Sync the CISA Known Exploited Vulnerabilities (KEV) catalog with "
        "nb_risk Vulnerabilities. Also runs automatically as a daily background job."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes',
        )

    def handle(self, *args, **options):
        if options['dry_run']:
            self.stdout.write("Dry run — no changes will be made.\n")
            catalog = fetch_kev_catalog()
            if not catalog:
                self.stderr.write("Failed to fetch KEV catalog.")
                return

            from nb_risk.models import Vulnerability
            matches = Vulnerability.objects.filter(cve__in=list(catalog.keys()))
            self.stdout.write(
                f"KEV catalog has {len(catalog)} entries.\n"
                f"Found {matches.count()} matching Vulnerability records:\n"
            )
            for v in matches:
                entry = catalog.get(v.cve.upper(), {})
                self.stdout.write(
                    f"  {v.cve} — {v.name} "
                    f"(ransomware: {entry.get('knownRansomwareCampaignUse', 'Unknown')})\n"
                )
            return

        updated, cleared, total = sync_kev_to_db(stdout=self.stdout)
        self.stdout.write(
            self.style.SUCCESS(
                f"\nKEV sync complete: {updated} updated, {cleared} cleared, "
                f"{total} total entries in catalog."
            )
        )
