import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

from django.core.wsgi import get_wsgi_application
from django.core.management import call_command

# Kusa nitong lilikhain ang django_session at lahat ng mga kinakailangang database tables
try:
    call_command('migrate', interactive=False)
except Exception as e:
    print(f"Migration error: {e}")

app = get_wsgi_application()