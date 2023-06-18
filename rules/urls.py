from rules import views
from django.urls import path
from rest_framework import routers

router = routers.SimpleRouter()
router.register("valid_ips", views.ValidIpsView)
router.register("my_rules", views.RulesView)

app_name = "rules"
urlpatterns = [
    path("", views.RulesList.as_view(), name="list"),
    path("assign_owner/", views.AssignOwner.as_view(), name="assign_owner"),
    path("device_info/", views.DeviceInfo.as_view(), name="device_info"),
] 
urlpatterns += router.urls
urlpatterns += [path("<str:pk>/", views.DetailRule.as_view(), name="detail")]