from django.urls import path, include
from .views import create_scan_result, get_scan_results, signup
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    # Scanner endpoints
    path("scan/", create_scan_result, name="create_scan_result"),
    path("results/", get_scan_results, name="get_scan_results"),

    # Auth (custom signup + JWT)
    path("signup/", signup, name="signup"),
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/register/", signup, name="register_user"),

    # dj-rest-auth / allauth endpoints
    path("auth/", include("dj_rest_auth.urls")),
    path("auth/registration/", include("dj_rest_auth.registration.urls")),
    path("auth/social/", include("allauth.socialaccount.urls")),
]
