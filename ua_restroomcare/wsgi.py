import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ua_restroomcare.settings')

# Optional admin bootstrap on Vercel cold start. Credentials come from environment
# variables (Vercel -> Project Settings -> Environment Variables); nothing is hard-coded.
#   ADMIN_BOOTSTRAP_USERNAME  (default: "nash")
#   ADMIN_BOOTSTRAP_PASSWORD  (required; if unset the bootstrap is skipped)
_bootstrap_password = os.environ.get('ADMIN_BOOTSTRAP_PASSWORD')

if os.environ.get('VERCEL') and _bootstrap_password:
    from django.core.management import call_command
    import django

    django.setup()

    # 1. Run migrations
    call_command('migrate', interactive=False)

    # 2. Ensure the superuser & UserProfile with role='admin' exist
    from django.contrib.auth import get_user_model
    from core.models import UserProfile

    User = get_user_model()
    username = os.environ.get('ADMIN_BOOTSTRAP_USERNAME', 'nash')

    user, created = User.objects.get_or_create(username=username, defaults={'email': 'admin@example.com'})
    # Only re-hash when needed: set_password() uses a random salt, so calling it on every
    # cold start changes the password hash and invalidates every logged-in session.
    if created or not user.check_password(_bootstrap_password):
        user.set_password(_bootstrap_password)
    user.is_superuser = True
    user.is_staff = True
    user.save()

    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.role = 'admin'
    profile.save()

application = app = get_wsgi_application()
