from django.urls import path, include
from utilities.urls import get_model_urls
from netbox.views.generic import ObjectChangeLogView, ObjectJournalView

from . import models, views, cve

app_name = 'nb_risk'

urlpatterns = (
    # ThreatSource URLs
    path(
        "threat-source/", views.ThreatSourceListView.as_view(), name="threatsource_list"
    ),
    path(
        "threat-source/add/",
        views.ThreatSourceEditView.as_view(),
        name="threatsource_add",
    ),
    path(
        "threat-source/<int:pk>/", views.ThreatSourceView.as_view(), name="threatsource"
    ),
    path(
        "threat-source/<int:pk>/edit/",
        views.ThreatSourceEditView.as_view(),
        name="threatsource_edit",
    ),
    path(
        "threat-source/<int:pk>/delete/",
        views.ThreatSourceDeleteView.as_view(),
        name="threatsource_delete",
    ),
    path(
        "threat-source/<int:pk>/changelog/",
        ObjectChangeLogView.as_view(),
        name="threatsource_changelog",
        kwargs={"model": models.ThreatSource},
    ),
    # ThreatEvent URLs
    path("threat-event/", views.ThreatEventListView.as_view(), name="threatevent_list"),
    path(
        "threat-event/add/", views.ThreatEventEditView.as_view(), name="threatevent_add"
    ),
    path("threat-event/<int:pk>/", views.ThreatEventView.as_view(), name="threatevent"),
    path('threat-event/<int:pk>/', include(get_model_urls(app_name, 'threatevent'))),
    path(
        "threat-event/<int:pk>/edit/",
        views.ThreatEventEditView.as_view(),
        name="threatevent_edit",
    ),
    path(
        "threat-event/<int:pk>/delete/",
        views.ThreatEventDeleteView.as_view(),
        name="threatevent_delete",
    ),
    path(
        "threat-event/delete/",
        views.ThreatEventBulkDeleteView.as_view(),
        name="threatevent_bulk_delete",
    ),
    # Vulnerability URLs
    path(
        "vulnerability/",
        views.VulnerabilityListView.as_view(),
        name="vulnerability_list",
    ),
    path(
        "vulnerability/add/",
        views.VulnerabilityEditView.as_view(),
        name="vulnerability_add",
    ),
    path(
        "vulnerability/<int:pk>/",
        views.VulnerabilityView.as_view(),
        name="vulnerability",
    ),
    path(
        "vulnerability/<int:pk>/edit/",
        views.VulnerabilityEditView.as_view(),
        name="vulnerability_edit",
    ),
    path('vulnerability/import/', views.VulnerabilityBulkImportView.as_view(), name='vulnerability_import'),
    path(
        "vulnerability/<int:pk>/delete/",
        views.VulnerabilityDeleteView.as_view(),
        name="vulnerability_delete",
    ),
    path(
        "vulnerability/delete/",
        views.VulnerabilityBulkDeleteView.as_view(),
        name="vulnerability_bulk_delete",
    ),
    path('vulnerability/<int:pk>/', include(get_model_urls(app_name, 'vulnerability'))),
    path(
        "vulnerability/search/",
        cve.VulnerabilitySearchView.as_view(),
        name="vulnerability_search",
    ),
    # VulnerabilityAssignment URLs
    path(
        "vulnerability-assignments/add/",
        views.VulnerabilityAssignmentEditView.as_view(),
        name="vulnerabilityassignment_add",
    ),
    path("vulnerability-assignments/",
        views.VulnerabilityAssignmentListView.as_view(),
        name="vulnerabilityassignment_list",
    ),
    path(
        "vulnerability-assignments/<int:pk>/delete/",
        views.VulnerabilityAssignmentDeleteView.as_view(),
        name="vulnerabilityassignment_delete",
    ),
    # Risk URLs
    path("risk/", views.RiskListView.as_view(), name="risk_list"),
    path("risk/add/", views.RiskEditView.as_view(), name="risk_add"),
    path("risk/<int:pk>/", views.RiskView.as_view(), name="risk"),
    path("risk/<int:pk>/edit/", views.RiskEditView.as_view(), name="risk_edit"),
    path("risk/<int:pk>/delete/", views.RiskDeleteView.as_view(), name="risk_delete"),
    path("risk/delete/", views.RiskBulkDeleteView.as_view(), name="risk_bulk_delete"),
    path(
        "risk/<int:pk>/changelog/",
        ObjectChangeLogView.as_view(),
        name="risk_changelog",
        kwargs={"model": models.Risk},
    ),
    path(
        "risk/<int:pk>/journal/",
        ObjectJournalView.as_view(),
        name="risk_journal",
        kwargs={"model": models.Risk},
    ),
    # Control URLs
    path("control/", views.ControlListView.as_view(), name="control_list"),
    path("control/add/", views.ControlEditView.as_view(), name="control_add"),
    path("control/<int:pk>/", views.ControlView.as_view(), name="control"),
    path("control/<int:pk>/edit/", views.ControlEditView.as_view(), name="control_edit"),
    path(
        "control/<int:pk>/delete/", views.ControlDeleteView.as_view(), name="control_delete"
    ),
    path(
        "control/delete/", views.ControlBulkDeleteView.as_view(), name="control_bulk_delete"
    ),
    path('control/<int:pk>/', include(get_model_urls(app_name, 'control'))),
    
)
