import django_tables2 as tables
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.http import urlencode


class CreateColumn(tables.Column):
    attrs = {'td': {'class': 'text-end text-nowrap'}}

    def render(self, record):
        cve = record['id']
        description = record['description']
        print(cve)
        url = reverse('plugins:nb_risk:vulnerability_add')
        query = {
            'cve': cve,
            'notes': description,
            'name': cve
        }
        encoded_query = urlencode(query)
        url = f'{url}?{encoded_query}'


        html = f'<a href={url} class="btn btn-primary btn-sm"><i class="mdi mdi-plus" aria-hidden="true"></i></a>'
        return mark_safe(html)
        