from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

def root_redirect(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')

urlpatterns = [
    # Safe root redirect based on auth status (prevents infinite loops)
    path('', root_redirect, name='root'),
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
]