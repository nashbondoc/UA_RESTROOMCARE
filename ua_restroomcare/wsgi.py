import os
import shutil
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

# Initialize Django environment
django.setup()

from django.core.management import call_command
from django.core.wsgi import get_wsgi_application

def initialize_database():
    """Ensure database exists in /tmp and carries all migrated tables."""
    db_path = '/tmp/db.sqlite3'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    source_db = os.path.join(base_dir, 'db.sqlite3')

    # Copy existing db.sqlite3 if available
    if os.path.exists(source_db) and not os.path.exists(db_path):
        try:
            shutil.copyfile(source_db, db_path)
        except Exception as e:
            print("Copy DB Error:", e)

    # Force migrations on /tmp/db.sqlite3 to create auth_user and core tables
    try:
        call_command('migrate', interactive=False)
    except Exception as e:
        print("Migration Error:", e)

# Run initialization during WSGI load
if os.environ.get('VERCEL') or not os.path.exists('/tmp/db.sqlite3'):
    initialize_database()

application = get_wsgi_application()
app = application