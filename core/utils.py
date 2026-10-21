from django.utils import timezone
import datetime
from .models import RestroomReport, SuspiciousActivityLog, AuditLog

def check_rate_limit_and_duplicates(user, location, category, is_urgent):
    now = timezone.now()
    thirty_minutes_ago = now - datetime.timedelta(minutes=30)
    
    # Check rate limit (Max 3 reports in 30 mins) unless marked urgent
    recent_reports_count = RestroomReport.objects.filter(
        user=user,
        created_at__gte=thirty_minutes_ago
    ).count()

    if recent_reports_count >= 3 and not is_urgent:
        # Flag suspicious activity
        SuspiciousActivityLog.objects.create(
            user=user,
            reason=f"Exceeded submission rate limit (Submitted {recent_reports_count + 1} reports in 30 minutes)."
        )
        return False, "Rate limit reached. You can only submit up to 3 reports per 30 minutes. Non-urgent submissions are temporarily paused.", None

    # Check active duplicate report for the same restroom and category
    existing_duplicate = RestroomReport.objects.filter(
        location=location,
        category=category,
        status__in=['Pending', 'Under Review', 'Verified', 'In Progress']
    ).first()

    if existing_duplicate:
        return False, f"An active report already exists for this restroom and concern category.", existing_duplicate

    return True, None, None

def log_audit_event(actor, action, details="", request=None):
    ip = None
    if request:
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
    AuditLog.objects.create(actor=actor, action=action, details=details, ip_address=ip)