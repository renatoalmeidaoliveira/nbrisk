from django.urls import path
from netbox.views.generic import ObjectChangeLogView

from . import models, views

urlpatterns  = (

    # ThreatSource URLs

    path('threat-source/', views.ThreatSourceListView.as_view(), name='threatsource_list'),
    path('threat-source/add/', views.ThreatSourceEditView.as_view(), name='threatsource_add'),
    path('threat-source/<int:pk>/', views.ThreatSourceView.as_view(), name='threatsource'),
    path('threat-source/<int:pk>/edit/', views.ThreatSourceEditView.as_view(), name='threatsource_edit'),
    path('threat-source/<int:pk>/delete/', views.ThreatSourceDeleteView.as_view(), name='threatsource_delete'),
    path('threat-source/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='threatsource_changelog', kwargs={
        'model': models.ThreatSource
    }),

    # ThreatEvent URLs

    path('threat-event/', views.ThreatEventListView.as_view(), name='threatevent_list'),
    path('threat-event/add/', views.ThreatEventEditView.as_view(), name='threatevent_add'),
    path('threat-event/<int:pk>/', views.ThreatEventView.as_view(), name='threatevent'),
    path('threat-event/<int:pk>/edit/', views.ThreatEventEditView.as_view(), name='threatevent_edit'),
    path('threat-event/<int:pk>/delete/', views.ThreatEventDeleteView.as_view(), name='threatevent_delete'),
    path('threat-event/delete/', views.ThreatEventBulkDeleteView.as_view(), name='threatevent_bulk_delete'),
    path('threat-event/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='threatevent_changelog', kwargs={
        'model': models.ThreatEvent
    }),

    # Vulnerability URLs

    path('vulnerability/', views.VulnerabilityListView.as_view(), name='vulnerability_list'),
    path('vulnerability/add/', views.VulnerabilityEditView.as_view(), name='vulnerability_add'),
    path('vulnerability/<int:pk>/', views.VulnerabilityView.as_view(), name='vulnerability'),
    path('vulnerability/<int:pk>/edit/', views.VulnerabilityEditView.as_view(), name='vulnerability_edit'),
    path('vulnerability/<int:pk>/delete/', views.VulnerabilityDeleteView.as_view(), name='vulnerability_delete'),
    path('vulnerability/delete/', views.VulnerabilityBulkDeleteView.as_view(), name='vulnerability_bulk_delete'),
    path('vulnerability/<int:pk>/changelog/', ObjectChangeLogView.as_view(), name='vulnerability_changelog', kwargs={
        'model': models.Vulnerability
    }),
    path('vulnerability/<int:pk>/affected-assets/', views.VulnerabilityAffectedAssetsView.as_view(), name='vulnerability_affected_assets'),

    # VulnerabilityAssignment URLs
    path('vulnerability-assignments/add/', views.VulnerabilityAssignmentEditView.as_view(), name='vulnerabilityassignment_add'),
    path('vulnerability-assignments/<int:pk>/delete/', views.VulnerabilityAssignmentDeleteView.as_view(), name='vulnerabilityassignment_delete'),

    
)