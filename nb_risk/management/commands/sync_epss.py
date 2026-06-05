"""
Management command wrapper for SyncEPSSJob.

Prefer triggering via the NetBox UI (Risk Assessment → CVE Integration →
Sync Jobs) or the background job scheduler. This command is retained for
environments where direct CLI access is available (bare-metal, dev).
"""

from django.core.management.base import BaseCommand
from nb_risk.epss import fetch_epss_scores, sync_epss_to_db


class Command(BaseCommand):
    help = (
        "Sync EPSS scores from FIRST.org for all nb_risk Vulnerabilities "
        "with a CVE ID. Also runs automatically as a daily background job."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what scores would be updated without making changes',
        )

    def handle(self, *args, **options):
        if options['dry_run']:
            from nb_risk.models import Vulnerability
            vulns = list(Vulnerability.objects.exclude(cve="").values_list('pk', 'cve', 'name'))
            if not vulns:
                self.stdout.write("No vulnerabilities with CVE IDs found.")
                return

            self.stdout.write(f"Dry run — fetching EPSS for {len(vulns)} vulnerabilities...\n")
            cve_ids = [cve for _, cve, _ in vulns]
            scores = fetch_epss_scores(cve_ids)

            self.stdout.write(f"Received scores for {len(scores)} CVEs:\n")
            for pk, cve, name in sorted(
                vulns,
                key=lambda x: scores.get(x[1].upper(), {}).get('epss', 0),
                reverse=True,
            ):
                data = scores.get(cve.upper())
                if data:
                    self.stdout.write(
                        f"  {cve}: EPSS={data['epss']:.4f} "
                        f"({data['percentile']*100:.1f}th percentile) — {name}\n"
                    )
            return

        updated, total = sync_epss_to_db(stdout=self.stdout)
        self.stdout.write(
            self.style.SUCCESS(
                f"\nEPSS sync complete: {updated}/{total} vulnerabilities updated."
            )
        )
