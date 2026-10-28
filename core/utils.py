from django.utils import timezone
import datetime
from .models import RestroomReport, SuspiciousActivityLog, AuditLog


def get_client_ip(request):
    if not request:
        return None
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def check_rate_limit_and_duplicates(user, location, category, is_urgent=False, request=None):
    now = timezone.now()
    one_hour_ago = now - datetime.timedelta(hours=1)
    ip = get_client_ip(request)

    # 1. Hourly Rate Limit Check (Max 3 reports per hour)
    recent_reports_count = RestroomReport.objects.filter(
        user=user,
        created_at__gte=one_hour_ago
    ).count()

    MAX_HOURLY_LIMIT = 3
    if recent_reports_count >= MAX_HOURLY_LIMIT:
        reason_text = (
            f"Hourly submission limit exceeded: {recent_reports_count + 1} submissions attempted within 1 hour."
        )
        SuspiciousActivityLog.objects.create(
            user=user,
            reason=reason_text,
            ip_address=ip
        )
        log_audit_event(
            user,
            "Rate Limit Violation",
            f"Blocked from submitting report at {location}. Reached {recent_reports_count} submissions/hr limit.",
            request
        )
        return False, (
            f"Rate Limit Exceeded: You have reached the hourly submission limit of {MAX_HOURLY_LIMIT} reports per hour. "
            "Please wait before submitting another report."
        ), None

    # 2. Duplicate Active Report Check for same location and category
    active_statuses = ['Pending', 'Under Review', 'Verified', 'In Progress']
    existing_duplicate = RestroomReport.objects.filter(
        location=location,
        category=category,
        status__in=active_statuses
    ).order_by('-created_at').first()

    if existing_duplicate:
        category_name = existing_duplicate.get_category_display() if hasattr(existing_duplicate, 'get_category_display') else category
        reason_text = (
            f"Duplicate report attempted for Location '{location}' and Category '{category}'. "
            f"Active Report #{existing_duplicate.id} is currently '{existing_duplicate.status}'."
        )
        SuspiciousActivityLog.objects.create(
            user=user,
            reason=reason_text,
            ip_address=ip
        )
        log_audit_event(
            user,
            "Duplicate Report Blocked",
            f"Attempted duplicate report for {location} ({category}). Active report #{existing_duplicate.id} exists with status '{existing_duplicate.status}'.",
            request
        )
        return False, (
            f"Duplicate Report Blocked: An active maintenance report (#{existing_duplicate.id}) already exists "
            f"for {location} under category '{category_name}'. Current status: '{existing_duplicate.status}'."
        ), existing_duplicate

    return True, None, None


def log_audit_event(actor, action, details="", request=None):
    ip = get_client_ip(request)
    # Ensure actor is a valid User instance or None
    user_actor = actor if getattr(actor, 'is_authenticated', False) else None
    AuditLog.objects.create(
        actor=user_actor,
        action=action,
        details=details,
        ip_address=ip
    )
