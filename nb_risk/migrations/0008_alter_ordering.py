# Generated migration for NetBox 4.5.x compatibility
# Adds Meta.ordering = ('name',) to all models for deterministic API pagination

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('nb_risk', '0007_remove_vulnerability_unique_vuln_name_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='threatsource',
            options={'ordering': ('name',)},
        ),
        migrations.AlterModelOptions(
            name='vulnerability',
            options={'ordering': ('name',), 'verbose_name': 'Vulnerability', 'verbose_name_plural': 'Vulnerabilities'},
        ),
        migrations.AlterModelOptions(
            name='vulnerabilityassignment',
            options={'ordering': ('pk',)},
        ),
        migrations.AlterModelOptions(
            name='threatevent',
            options={'ordering': ('name',)},
        ),
        migrations.AlterModelOptions(
            name='risk',
            options={'ordering': ('name',)},
        ),
        migrations.AlterModelOptions(
            name='control',
            options={'ordering': ('name',)},
        ),
    ]
