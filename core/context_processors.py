from django.conf import settings
from .models import UserProfile

def google_oauth_settings(request):
    """Expose Google OAuth Client ID and admin stats safely."""
    pending_count = 0
    user = getattr(request, 'user', None)
    if user and user.is_authenticated and (user.is_superuser or user.is_staff or getattr(getattr(user, 'profile', None), 'role', None) == 'admin'):
        try:
            pending_count = UserProfile.objects.filter(is_verified=False, role='student').count()
        except Exception:
            pending_count = 0

    return {
        'GOOGLE_CLIENT_ID': getattr(settings, 'GOOGLE_CLIENT_ID', ''),
        'pending_verifications_count': pending_count,
    }

