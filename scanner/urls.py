# from django.urls import path, include
# from .views import create_scan_result, get_scan_results, signup, signin, me
# from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# from . import views  

# urlpatterns = [
#     # Scanner endpoints
#     path("scan/", create_scan_result, name="create_scan_result"),
#     path("results/", get_scan_results, name="get_scan_results"),

#     # Custom auth (your JWT-enabled views)
#     path("signup/", signup, name="signup"),
#     path("signin/", signin, name="signin"),
#      path("me/", me, name="me"), 
#     # JWT utility endpoints (optional but recommended)
#     path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
#     path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

#     path("search/", views.search_scan_results, name="search_scan_results"),

#     # dj-rest-auth / allauth endpoints (social login, registration, etc.)
#     path("auth/", include("dj_rest_auth.urls")),
#     path("auth/registration/", include("dj_rest_auth.registration.urls")),
#     path("auth/social/", include("allauth.socialaccount.urls")),
# ]


from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views  

urlpatterns = [
    # Scanner endpoints
    path("scan/", views.create_scan_result, name="create_scan"),
    path("results/<int:scan_id>/", views.get_scan_result_by_id, name="scan_result"),  # Get result by ID
    path("results/", views.get_scan_results, name="latest_scan"),  # Get latest scan only
    path("findings/", views.findings, name="findings"),  # ✅ add findings filter endpoint

    # Custom auth (your JWT-enabled views)
    path("signup/", views.signup, name="signup"),
    path("signin/", views.signin, name="signin"),
    path("me/", views.me, name="me"), 

    # JWT utility endpoints
    path("auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),

    # Search endpoint
    path("search/", views.search_scan_results, name="search_scan_results"),

    # dj-rest-auth / allauth endpoints (optional: social login, registration, etc.)
    path("auth/", include("dj_rest_auth.urls")),
    path("auth/registration/", include("dj_rest_auth.registration.urls")),
    path("auth/social/", include("allauth.socialaccount.urls")),
]
