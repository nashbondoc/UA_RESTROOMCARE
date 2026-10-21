import os
import shutil
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

# Run migrations and setup database in /tmp for Vercel environment
if os.environ.get('VERCEL'):
    from django.core.management import call_command
    import django
    
    django.setup()
    
    # 1. Run migrations to create tables
    call_command('migrate', interactive=False)
    
    # 2. Automatically create/reset admin superuser if missing
    from django.contrib.auth import get_user_model
    User = get_user_model()
    
    username = "nash"
    password = "12345"
    
    if not User.objects.filter(username=username).exists():
        User.objects.create_superuser(username=username, email="admin@example.com", password=password)
    else:
        # Update password just in case
        user = User.objects.get(username=username)
        user.set_password(password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

app = get_wsgi_application()