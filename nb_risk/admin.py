from django.contrib import admin
from . import models

@admin.register(models.VulnerabilityAssignment)
class VulnerabilityAssignmentAdmin(admin.ModelAdmin):
    fields = ["asset_object_type", "asset_id", "vulnerability"]