import os
import shutil
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

# Setup Django first before calling migrations or DB operations
django.setup()

from django.core.management import call_command
from django.core.wsgi import get_wsgi_application

# Ensure DB exists and tables are migrated in /tmp/db.sqlite3
if os.environ.get('VERCEL'):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    source_db = os.path.join(base_dir, 'db.sqlite3')
    target_db = '/tmp/db.sqlite3'

    if os.path.exists(source_db) and not os.path.exists(target_db):
        shutil.copyfile(source_db, target_db)

    try:
        call_command('migrate', interactive=False)
    except Exception as e:
        print("Migration error on startup:", e)

application = get_wsgi_application()
app = application