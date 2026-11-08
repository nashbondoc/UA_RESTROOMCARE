from django.conf import settings

def google_oauth_settings(request):
    """Expose Google OAuth Client ID to templates safely."""
    return {
        'GOOGLE_CLIENT_ID': getattr(settings, 'GOOGLE_CLIENT_ID', ''),
    }

