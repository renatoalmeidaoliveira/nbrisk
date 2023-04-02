import django_tables2 as tables
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.http import urlencode


class CreateColumn(tables.Column):
    attrs = {"td": {"class": "text-end text-nowrap"}}

    def render(self, record):
        cve = record["id"]
        description = record["description"]
        accessVector = record["accessVector"]
        accessComplexity = record["accessComplexity"]
        authentication = record["authentication"]
        confidentialityImpact = record["confidentialityImpact"]
        integrityImpact = record["integrityImpact"]
        availabilityImpact = record["availabilityImpact"]
        baseScore = record["baseScore"]

        url = reverse("plugins:nb_risk:vulnerability_add")
        query = {
            "cve": cve,
            "notes": description,
            "name": cve,
            "cvssaccessVector": accessVector,
            "cvssaccessComplexity": accessComplexity,
            "cvssauthentication": authentication,
            "cvssconfidentialityImpact": confidentialityImpact,
            "cvssintegrityImpact": integrityImpact,
            "cvssavailabilityImpact": availabilityImpact,
            "cvssbaseScore": baseScore,
        }
        encoded_query = urlencode(query)
        url = f"{url}?{encoded_query}"

        html = f'<a href={url} class="btn btn-primary btn-sm"><i class="mdi mdi-plus" aria-hidden="true"></i></a>'
        return mark_safe(html)
