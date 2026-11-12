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
    # Only re-hash when needed: set_password() uses a random salt, so calling it on every
    # cold start changes the password hash and invalidates every logged-in session
    # (Django ties the session to the password hash) -> admin gets logged out.
    if created or not user.check_password(password):
        user.set_password(password)
    user.is_superuser = True
    user.is_staff = True
    user.save()

    # Siguraduhing may UserProfile as Admin
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.role = 'admin'
    profile.save()

application = app = get_wsgi_application()
