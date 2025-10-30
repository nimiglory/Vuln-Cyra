# from django.contrib import admin
# from django.urls import path, include
# from scanner import views


# urlpatterns = [
#     path("admin/", admin.site.urls),
    
#     # Scanner routes
#     path("api/", include("scanner.urls")),  # connects to scanner/urls.py
#     path('accounts/', include('allauth.urls')),
#      path("", views.home, name="home"), 
# ]

# # 

from django.contrib import admin
from django.urls import path, include
from scanner import views
from django.http import HttpResponse

def home(request):
    return HttpResponse("Welcome to Vuln Cyra 🚀 Your backend is live!")

urlpatterns = [
    path("", home, name="home"),
    path("admin/", admin.site.urls),
    path("api/", include("scanner.urls")),  
    path("accounts/", include("allauth.urls")), 
  
]
