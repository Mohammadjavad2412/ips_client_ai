from rules import views
from django.urls import path

app_name = "rules"
urlpatterns = [
    path("list", views.RulesList.as_view(), name="list"),
    path("enable/", views.EnableRule.as_view(), name="enable"),
    path("my_rules/", views.MyRules.as_view(), name="my_rules"),
    path("detail/<str:pk>/", views.DetailRule.as_view(), name="detail"),
    path("disable/<str:rule_name>/", views.DisableRule.as_view(), name="disable"),
    path("set_home_net/", views.SetHomeNet.as_view(), name="set_home_net")
]

