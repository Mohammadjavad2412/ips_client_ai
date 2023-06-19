from rest_framework import routers
from user_manager.views import UserView
from django.urls import path
from user_manager import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

router = routers.SimpleRouter()
router.register("", UserView)

app_name = "users"
urlpatterns = [
    path("server_auth/", views.ServerAuthentication.as_view(), name="server_auth"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogOutView.as_view(), name="logout"),
    path("token/", TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("product/", views.ProductView.as_view(), name="products")
]
urlpatterns += router.urls