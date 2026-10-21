import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

if os.environ.get('VERCEL'):
    from django.core.management import call_command
    import django
    
    django.setup()
    
    # 1. Run migrations
    call_command('migrate', interactive=False)
    
    # 2. Auto-create Superuser & UserProfile with role='admin'
    from django.contrib.auth import get_user_model
    from core.models import UserProfile
    
    User = get_user_model()
    username = "nash"
    password = "12345"
    
    user, created = User.objects.get_or_create(username=username, defaults={'email': 'admin@example.com'})
    user.set_password(password)
    user.is_superuser = True
    user.is_staff = True
    user.save()
    
    # Siguraduhing may UserProfile as Admin
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.role = 'admin'
    profile.save()

app = get_wsgi_application()