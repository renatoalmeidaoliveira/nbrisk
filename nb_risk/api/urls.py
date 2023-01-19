from netbox.api.routers import NetBoxRouter
from . import views

app_name = 'nb_risk'

router = NetBoxRouter()

router.register('threatsource', views.ThreatSourceViewSet)
router.register('threatevent', views.ThreatEventViewSet)
router.register('vulnerability', views.VulnerabilityViewSet)
router.register('vulnerabilityassignment', views.VulnerabilityAssignmentViewSet)


urlpatterns = router.urls