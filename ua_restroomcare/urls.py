from django.contrib import admin
from django.urls import path, include, re_path

from core import views as core_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),
    # Authenticated media: ID cards & incident photos are stored in the database (core.StoredFile)
    re_path(r'^media/(?P<path>.+)$', core_views.protected_media, name='protected_media'),
]
