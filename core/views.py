from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import RestroomReport, RestroomLocation, AuditLog, SuspiciousActivityLog, UserProfile
from .forms import RestroomReportForm
from .utils import check_rate_limit_and_duplicates, log_audit_event

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            log_audit_event(user, "User Login", "Successful authentication", request)
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, 'core/login.html', {'form': form})

@login_required
def logout_view(request):
    log_audit_event(request.user, "User Logout", "Logged out safely", request)
    logout(request)
    return redirect('login')

@login_required
def dashboard(request):
    profile = getattr(request.user, 'profile', None)
    if profile and profile.role == 'admin':
        return redirect('admin_dashboard')
    
    user_reports = RestroomReport.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'core/user_dashboard.html', {'reports': user_reports, 'profile': profile})

@login_required
def submit_report(request):
    if request.method == 'POST':
        form = RestroomReportForm(request.POST, request.FILES)
        if form.is_valid():
            location = form.cleaned_data['location']
            category = form.cleaned_data['category']
            is_urgent = form.cleaned_data['is_urgent']

            # Run Anti-Spam and Duplicate checks
            allowed, error_msg, duplicate_report = check_rate_limit_and_duplicates(
                request.user, location, category, is_urgent
            )

            if not allowed:
                messages.error(request, error_msg)
                if duplicate_report:
                    messages.info(request, f"Existing Report #{duplicate_report.id} status is: '{duplicate_report.status}'.")
                return render(request, 'core/submit_report.html', {'form': form})

            report = form.save(commit=False)
            report.user = request.user
            report.save()

            log_audit_event(request.user, "Submitted Report", f"Created Report #{report.id} at {location}", request)
            messages.success(request, f"Report #{report.id} submitted successfully.")
            return redirect('dashboard')
    else:
        form = RestroomReportForm()

    return render(request, 'core/submit_report.html', {'form': form})

@login_required
def admin_dashboard(request):
    # RBAC Check: Ensure authorized personnel only
    profile = getattr(request.user, 'profile', None)
    if not profile or profile.role != 'admin':
        log_audit_event(request.user, "Unauthorized Access Attempt", "Attempted to view Admin Dashboard", request)
        messages.error(request, "Access denied. Administrative privileges required.")
        return redirect('dashboard')

    reports = RestroomReport.objects.all().order_by('-created_at')
    stats = {
        'total': reports.count(),
        'pending': reports.filter(status='Pending').count(),
        'under_review': reports.filter(status='Under Review').count(),
        'in_progress': reports.filter(status='In Progress').count(),
        'resolved': reports.filter(status='Resolved').count(),
        'suspicious': SuspiciousActivityLog.objects.filter(reviewed=False).count()
    }
    suspicious_logs = SuspiciousActivityLog.objects.filter(reviewed=False)

    return render(request, 'core/admin_dashboard.html', {
        'reports': reports,
        'stats': stats,
        'suspicious_logs': suspicious_logs
    })

@login_required
def update_report_status(request, report_id):
    profile = getattr(request.user, 'profile', None)
    if not profile or profile.role != 'admin':
        messages.error(request, "Access Denied.")
        return redirect('dashboard')

    report = get_object_or_404(RestroomReport, id=report_id)
    if request.method == 'POST':
        new_status = request.POST.get('status')
        rejection_reason = request.POST.get('rejection_reason', '')

        old_status = report.status
        report.status = new_status
        if new_status == 'Rejected':
            report.rejection_reason = rejection_reason
        report.save()

        log_audit_event(
            request.user, 
            "Updated Report Status", 
            f"Changed Report #{report.id} status from '{old_status}' to '{new_status}'. Reason: {rejection_reason}", 
            request
        )
        messages.success(request, f"Report #{report.id} status updated to {new_status}.")
        return redirect('admin_dashboard')

@login_required
def audit_logs_view(request):
    profile = getattr(request.user, 'profile', None)
    if not profile or profile.role != 'admin':
        messages.error(request, "Access Denied.")
        return redirect('dashboard')

    logs = AuditLog.objects.all().order_by('-timestamp')[:100]
    return render(request, 'core/audit_logs.html', {'logs': logs})