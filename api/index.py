import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

from django.core.wsgi import get_wsgi_application

app = get_wsgi_application()