from rules import views
from django.urls import path
from rest_framework import routers

router = routers.SimpleRouter()
router.register("valid_ips", views.ValidIpsView)

app_name = "rules"
urlpatterns = [
    path("list", views.RulesList.as_view(), name="list"),
    path("enable/", views.EnableRule.as_view(), name="enable"),
    path("my_rules/", views.MyRules.as_view(), name="my_rules"),
    path("detail/<str:pk>/", views.DetailRule.as_view(), name="detail"),
    path("disable/<str:rule_name>/", views.DisableRule.as_view(), name="disable"),
    path("assign_owner/", views.AssignOwner.as_view(), name="assign_owner"),
    path("device_info/", views.DeviceInfo.as_view(), name="device_info"),
    path("update/<str:pk>/", views.UpdateRule.as_view(), name="update")
] 
urlpatterns += router.urls
