import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dcim', '0001_initial'),
        ('nb_risk', '0008_alter_ordering'),
    ]

    operations = [
        migrations.CreateModel(
            name='CPEMapping',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created', models.DateTimeField(auto_now_add=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True, null=True)),
                ('custom_field_data', models.JSONField(blank=True, default=dict, encoder=None)),
                ('tags', models.ManyToManyField(blank=True, related_name='+', to='extras.tag')),
                ('platform', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='cpe_mappings',
                    to='dcim.platform',
                )),
                ('device_type', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='cpe_mappings',
                    to='dcim.devicetype',
                )),
                ('cpe_part', models.CharField(
                    choices=[('o', 'Operating System (o)'), ('a', 'Application (a)'), ('h', 'Hardware (h)')],
                    default='o', max_length=1, verbose_name='CPE Part',
                )),
                ('cpe_vendor', models.CharField(max_length=100, verbose_name='CPE Vendor')),
                ('cpe_product', models.CharField(max_length=100, verbose_name='CPE Product')),
                ('cpe_target_sw', models.CharField(blank=True, max_length=100, verbose_name='CPE Target Software')),
                ('verified', models.BooleanField(default=False, verbose_name='Verified')),
                ('notes', models.TextField(blank=True, verbose_name='Notes')),
            ],
            options={
                'verbose_name': 'CPE Mapping',
                'verbose_name_plural': 'CPE Mappings',
                'ordering': ('cpe_vendor', 'cpe_product'),
            },
        ),
    ]
