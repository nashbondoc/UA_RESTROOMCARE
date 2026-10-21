from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    # Redirect root URL (/) directly to /login/
    path('', lambda request: redirect('login', permanent=False)),
    path('admin/', admin.site.urls),
    path('', include('core.urls')),  # Includes dashboard, login, submit, etc.
]