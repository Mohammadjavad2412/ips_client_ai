from rest_framework import routers
from user_manager.views import UserView
from django.urls import path
from user_manager import views

router = routers.SimpleRouter()
router.register("", UserView)

app_name = "users"
urlpatterns = [
    path("server_auth/", views.ServerAuthentication.as_view(), name="server_auth"),
]
urlpatterns += router.urls