import re
import requests
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView
)
from django.urls import reverse_lazy
from django.contrib import messages
from django.db.models import Q

from .models import RestroomReport, RestroomLocation, AuditLog, SuspiciousActivityLog, UserProfile
from .forms import RestroomReportForm, StudentRegistrationForm, InstitutionalPasswordResetForm
from .utils import check_rate_limit_and_duplicates, log_audit_event, get_client_ip


def is_admin(user):
    """Check if the user has administrative privileges."""
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser or user.is_staff:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.role == 'admin')


def parse_ocr_text(image_file):
    """Safely parse text from an uploaded image file using Cloud OCR."""
    if not image_file:
        return ""
    try:
        image_file.seek(0)
        payload = {
            'apikey': 'helloworld',  # Standard API key for OCR.space
            'language': 'eng',
            'isOverlayRequired': False,
            'scale': True,
            'detectOrientation': True
        }
        files = {'file': (image_file.name, image_file.read(), image_file.content_type)}
        response = requests.post(
            'https://api.ocr.space/parse/image',
            files=files,
            data=payload,
            timeout=8
        )
        result = response.json()
        image_file.seek(0)

        if result.get('ParsedResults'):
            return result['ParsedResults'][0].get('ParsedText', '').lower()
    except Exception:
        pass
    finally:
        image_file.seek(0)
    return ""


# -------------------------------------------------------------
# 1. AUTHENTICATION & PORTAL ACCESS
# -------------------------------------------------------------

def login_view(request):
    """
    Main Student / Faculty Login Portal.
    - When valid credentials entered: logs in and redirects to User Dashboard.
    - When an Admin logs in through Main Portal: automatically redirects to Admin Dashboard.
    - If account pending verification: informs the user that review is underway.
    """
    if request.user.is_authenticated:
        if is_admin(request.user):
            return redirect('admin_dashboard')
        return redirect('dashboard')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        # Check if user exists but is currently deactivated (pending review)
        user_query = User.objects.filter(username__iexact=username).first()
        if user_query and user_query.check_password(password) and not user_query.is_active:
            messages.warning(
                request,
                "Your account registration is currently pending administrative verification. "
                "You will be granted access once your student ID has been confirmed."
            )
            return render(request, 'core/login.html', {'form': form, 'entered_username': username})

        if form.is_valid():
            user = form.get_user()
            login(request, user)

            if is_admin(user):
                log_audit_event(
                    user,
                    "Admin Login (Main Portal)",
                    "Admin logged in through Main Portal and was redirected to Admin Dashboard.",
                    request
                )
                messages.success(request, f"Welcome back, Administrator {user.get_full_name() or user.username}!")
                return redirect('admin_dashboard')
            else:
                log_audit_event(user, "User Login", "Authenticated via Main Portal.", request)
                messages.success(request, f"Welcome back, {user.get_full_name() or user.username}!")
                return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password. Please verify your credentials.")
            log_audit_event(
                None,
                "Failed Login Attempt",
                f"Failed authentication attempt for username '{username}'.",
                request
            )
    else:
        form = AuthenticationForm()

    return render(request, 'core/login.html', {'form': form})


def admin_login_view(request):
    """
    Dedicated Admin Portal (/admin-portal/login/).
    - When Admin enters valid credentials: logs in and redirects to Admin Dashboard.
    - When a Student/Teacher attempts login: blocks access immediately.
    """
    if request.user.is_authenticated:
        if is_admin(request.user):
            return redirect('admin_dashboard')
        messages.error(request, "Access Denied: This portal is strictly restricted to administrative personnel.")
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        user = User.objects.filter(username__iexact=username).first()
        if user and user.check_password(password):
            if not is_admin(user):
                log_audit_event(
                    user,
                    "Unauthorized Admin Portal Login Attempt",
                    f"Student/Faculty account '{username}' attempted to authenticate through Dedicated Admin Portal.",
                    request
                )
                SuspiciousActivityLog.objects.create(
                    user=user,
                    reason=f"Blocked student attempt to login via Dedicated Admin Portal.",
                    ip_address=get_client_ip(request)
                )
                messages.error(
                    request,
                    "Access Denied: This portal is strictly restricted to authorized administrative personnel."
                )
                return render(request, 'core/admin_login.html', {'entered_username': username})

            if not user.is_active:
                messages.error(request, "Your administrative account is currently deactivated. Please contact campus IT.")
                return render(request, 'core/admin_login.html', {'entered_username': username})

            login(request, user)
            log_audit_event(
                user,
                "Admin Portal Login",
                "Administrator successfully authenticated through Dedicated Admin Portal.",
                request
            )
            messages.success(request, f"Welcome to the Admin Control Center, {user.get_full_name() or user.username}!")
            return redirect('admin_dashboard')
        else:
            messages.error(request, "Invalid administrator credentials.")
            log_audit_event(
                None,
                "Failed Admin Portal Login",
                f"Failed login attempt on Admin Portal for username '{username}'.",
                request
            )

    return render(request, 'core/admin_login.html')


@login_required
def logout_view(request):
    """Safely logs out user and logs audit trail."""
    user = request.user
    log_audit_event(user, "User Logout", f"User {user.username} logged out safely.", request)
    logout(request)
    messages.info(request, "You have been logged out safely.")
    return redirect('login')


# -------------------------------------------------------------
# 2. STUDENT REGISTRATION & CLOUD OCR VERIFICATION
# -------------------------------------------------------------

def register_view(request):
    """
    Student Registration workflow:
    - Captures Student ID, Full Name, Institutional Email (@ua.edu.ph), Password,
      FRONT of ID (Photo/Name) and BACK of ID (Student ID number/Barcode).
    - Strict Duplication Check: Once an ID identity has been registered, it cannot be reused.
    - Cloud OCR Verification:
      - Back of ID is parsed for the critical Student ID number.
      - Front of ID is parsed for the Student Name.
      - Auto-activates if confirmed, else queues for manual review without exposing raw mechanics.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = StudentRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_front = request.FILES.get('id_picture')
            uploaded_back = request.FILES.get('id_picture_back')
            input_student_id = form.cleaned_data['student_id'].strip()
            input_first_name = form.cleaned_data['first_name'].strip()
            input_last_name = form.cleaned_data['last_name'].strip()
            input_email = form.cleaned_data['email'].strip().lower()

            # Strict Duplication Check Safeguard
            clean_target = re.sub(r'[^a-zA-Z0-9]', '', input_student_id).lower()
            for existing in UserProfile.objects.exclude(student_id__isnull=True).values_list('student_id', flat=True):
                if existing and re.sub(r'[^a-zA-Z0-9]', '', existing).lower() == clean_target:
                    messages.error(
                        request,
                        "Duplication Security Alert: An account with this Student ID has already been registered in the system. "
                        "Each identity cannot be used to create another account."
                    )
                    return render(request, 'core/register.html', {'form': form})

            is_auto_verified = False
            is_active_status = False

            # Clean strings for matching
            last_name_clean = input_last_name.lower()
            first_name_clean = input_first_name.lower()

            # 1. Parse Back of ID (where Student ID number is located)
            back_text = parse_ocr_text(uploaded_back)
            back_cleaned = re.sub(r'[^a-zA-Z0-9]', '', back_text)

            # 2. Parse Front of ID (where Name and Photo are located)
            front_text = parse_ocr_text(uploaded_front)
            front_cleaned = re.sub(r'[^a-zA-Z0-9]', '', front_text)

            combined_text = f"{back_text} {front_text}"
            combined_cleaned = f"{back_cleaned} {front_cleaned}"

            # Check for Student ID (primarily on back card)
            id_matched = (clean_target in back_cleaned) or (input_student_id.lower() in back_text) or (clean_target in combined_cleaned)
            # Check for Student Name (primarily on front card)
            name_matched = (last_name_clean in front_text) or (first_name_clean in front_text) or (last_name_clean in combined_text)

            if id_matched and name_matched:
                is_auto_verified = True
                is_active_status = True
                ocr_detail = f"ID '{input_student_id}' & Name '{input_last_name}' confirmed from front/back card."
                user_msg = "Identity Verified! Your Student ID details have been verified. You may now log in."
            elif id_matched or name_matched:
                ocr_detail = f"Partial card match (ID={id_matched}, Name={name_matched}). Sent to admin approval."
                user_msg = "Registration Received: Your student identity verification is pending administrative review."
            else:
                ocr_detail = "OCR scans unclear. Sent to manual admin review."
                user_msg = "Registration Received: Your student verification request has been queued for review."

            # Reset file pointers before model saving
            if uploaded_front:
                uploaded_front.seek(0)
            if uploaded_back:
                uploaded_back.seek(0)

            # Create User record
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.is_active = is_active_status
            user.save()

            # Create UserProfile record with Front and Back ID photos
            UserProfile.objects.create(
                user=user,
                role='student',
                student_id=input_student_id,
                id_picture=uploaded_front,
                id_picture_back=uploaded_back,
                is_verified=is_auto_verified
            )

            # Log audit event
            log_audit_event(
                user,
                "Student Registration Submitted",
                f"Student ID: {input_student_id} | Verified: {is_auto_verified} | Card Scans: {ocr_detail}",
                request
            )

            if is_auto_verified:
                messages.success(request, user_msg)
            else:
                messages.info(request, user_msg)

            return redirect('login')
    else:
        form = StudentRegistrationForm()

    return render(request, 'core/register.html', {'form': form})


# -------------------------------------------------------------
# 3. INCIDENT REPORTING & PHOTO EVIDENCE
# -------------------------------------------------------------

@login_required
def submit_report(request):
    """
    Incident Report Submission:
    - User selects Restroom Location and Issue Category (Plumbing, Cleanliness, Supplies, Damaged Fixtures, Other).
    - User inputs detailed description.
    - User attaches required photo evidence (enctype="multipart/form-data").
    - User toggles Urgent flag for high-priority incidents.
    """
    if request.method == 'POST':
        form = RestroomReportForm(request.POST, request.FILES)
        if form.is_valid():
            location = form.cleaned_data['location']
            category = form.cleaned_data['category']
            is_urgent = form.cleaned_data['is_urgent']

            # Anti-Spam & Duplicate Checks
            allowed, error_msg, duplicate_report = check_rate_limit_and_duplicates(
                user=request.user,
                location=location,
                category=category,
                is_urgent=is_urgent,
                request=request
            )

            if not allowed:
                messages.error(request, error_msg)
                if duplicate_report:
                    messages.info(
                        request,
                        f"Active Incident #{duplicate_report.id} was already reported for this facility. "
                        f"Current status: '{duplicate_report.status}'."
                    )
                return render(request, 'core/submit_report.html', {'form': form})

            report = form.save(commit=False)
            report.user = request.user
            report.save()

            log_audit_event(
                request.user,
                "Report Submitted",
                f"Incident Report #{report.id} submitted for {location} [{category}] (Urgent: {is_urgent}).",
                request
            )
            messages.success(
                request,
                f"Report #{report.id} submitted successfully! Maintenance personnel have been notified."
            )
            return redirect('dashboard')
        else:
            messages.error(request, "Please review the form. Ensure all required fields including photo evidence are provided.")
    else:
        form = RestroomReportForm()

    locations = RestroomLocation.objects.all().order_by('building', 'floor', 'room_number')
    return render(request, 'core/submit_report.html', {'form': form, 'locations': locations})


@login_required
def dashboard(request):
    """
    User Dashboard:
    - Redirects admins to admin dashboard.
    - Students view their submitted report history and real-time resolution status.
    """
    if is_admin(request.user):
        return redirect('admin_dashboard')

    profile = getattr(request.user, 'profile', None)
    user_reports = RestroomReport.objects.filter(user=request.user).order_by('-created_at')

    return render(request, 'core/user_dashboard.html', {
        'reports': user_reports,
        'profile': profile
    })


# -------------------------------------------------------------
# 4. MAINTENANCE MANAGEMENT & ADMINISTRATION
# -------------------------------------------------------------

@login_required
def admin_dashboard(request):
    """
    Admin Dashboard:
    - View system status metrics (Total Reports, Pending, Under Review, In Progress, Resolved).
    - View and manage pending student account verification requests (Approve / Reject) with Front and Back ID photos.
    - View and update report statuses with resolution or rejection notes.
    - View suspicious activity logs.
    """
    if not is_admin(request.user):
        log_audit_event(
            request.user,
            "Unauthorized Admin Access",
            "Non-admin user attempted to access the Admin Dashboard directly.",
            request
        )
        messages.error(request, "Access denied. Administrative privileges required.")
        return redirect('dashboard')

    reports = RestroomReport.objects.all().order_by('-created_at')
    pending_students = UserProfile.objects.filter(is_verified=False, role='student').select_related('user')
    suspicious_logs = SuspiciousActivityLog.objects.filter(reviewed=False).order_by('-flagged_at')[:20]

    stats = {
        'total': reports.count(),
        'pending': reports.filter(status='Pending').count(),
        'under_review': reports.filter(status='Under Review').count(),
        'in_progress': reports.filter(status='In Progress').count(),
        'resolved': reports.filter(status='Resolved').count(),
        'rejected': reports.filter(status='Rejected').count(),
        'suspicious': SuspiciousActivityLog.objects.filter(reviewed=False).count(),
        'pending_registrations': pending_students.count()
    }

    return render(request, 'core/admin_dashboard.html', {
        'reports': reports,
        'stats': stats,
        'suspicious_logs': suspicious_logs,
        'pending_students': pending_students
    })


@login_required
def verify_student(request, profile_id, action):
    """
    Admin verification of pending student registrations:
    - Approve: sets is_verified=True, user.is_active=True, logs audit trail.
    - Reject: deletes the student registration record, logs audit trail.
    """
    if not is_admin(request.user):
        messages.error(request, "Access Denied: Administrative privileges required.")
        return redirect('dashboard')

    target_profile = get_object_or_404(UserProfile, id=profile_id)
    student_user = target_profile.user
    student_name = student_user.get_full_name() or student_user.username
    student_id_no = target_profile.student_id or 'N/A'

    if action == 'approve':
        target_profile.is_verified = True
        student_user.is_active = True
        student_user.save()
        target_profile.save()

        log_audit_event(
            request.user,
            "Student Approved",
            f"Approved student account: {student_name} (ID: {student_id_no}, Email: {student_user.email})",
            request
        )
        messages.success(request, f"Student account for '{student_name}' has been verified and activated.")

    elif action == 'reject':
        log_audit_event(
            request.user,
            "Student Rejected",
            f"Rejected and deleted student registration for: {student_name} (ID: {student_id_no}, Email: {student_user.email})",
            request
        )
        student_user.delete()
        messages.warning(request, f"Student registration for '{student_name}' has been rejected and permanently removed.")

    return redirect('admin_dashboard')


@login_required
def update_report_status(request, report_id):
    """
    Admin status update with resolution / rejection notes:
    - Allows setting status to Pending, Under Review, In Progress, Resolved, or Rejected.
    - Attaches resolution or rejection notes.
    - Logs status updates to AuditLog.
    """
    if not is_admin(request.user):
        messages.error(request, "Access Denied.")
        return redirect('dashboard')

    report = get_object_or_404(RestroomReport, id=report_id)

    if request.method == 'POST':
        new_status = request.POST.get('status')
        resolution_notes = request.POST.get('resolution_notes', '').strip()

        old_status = report.status
        report.status = new_status
        if resolution_notes:
            report.resolution_notes = resolution_notes
            if new_status == 'Rejected':
                report.rejection_reason = resolution_notes

        report.save()

        notes_summary = f" Notes: '{resolution_notes}'" if resolution_notes else ""
        log_audit_event(
            request.user,
            "Report Status Update",
            f"Incident #{report.id} at {report.location} status changed from '{old_status}' to '{new_status}'.{notes_summary}",
            request
        )
        messages.success(request, f"Report #{report.id} status successfully updated to '{new_status}'.")

    return redirect('admin_dashboard')


@login_required
def mark_suspicious_reviewed(request, log_id):
    """Allows admin to mark suspicious activity log entries as reviewed."""
    if not is_admin(request.user):
        messages.error(request, "Access Denied.")
        return redirect('dashboard')

    log_entry = get_object_or_404(SuspiciousActivityLog, id=log_id)
    log_entry.reviewed = True
    log_entry.save()

    log_audit_event(
        request.user,
        "Security Review",
        f"Marked suspicious log #{log_entry.id} as reviewed.",
        request
    )
    messages.success(request, f"Suspicious activity entry #{log_id} marked as reviewed.")
    return redirect('admin_dashboard')


@login_required
def audit_logs_view(request):
    """
    Audit Logs tracking:
    - User authentication (login, logout, failed logins, admin logins)
    - Report creations
    - Student approvals & rejections
    - Status updates with resolution notes
    """
    if not is_admin(request.user):
        messages.error(request, "Access Denied: Administrative privileges required.")
        return redirect('dashboard')

    search_query = request.GET.get('q', '').strip()
    logs_qs = AuditLog.objects.select_related('actor').order_by('-timestamp')

    if search_query:
        logs_qs = logs_qs.filter(
            Q(action__icontains=search_query) |
            Q(details__icontains=search_query) |
            Q(actor__username__icontains=search_query) |
            Q(ip_address__icontains=search_query)
        )

    logs = logs_qs[:150]
    return render(request, 'core/audit_logs.html', {'logs': logs, 'search_query': search_query})


# -------------------------------------------------------------
# 5. ACCOUNT RECOVERY (PASSWORD RESET WORKFLOW)
# -------------------------------------------------------------

class CustomPasswordResetView(PasswordResetView):
    template_name = 'core/password_reset.html'
    form_class = InstitutionalPasswordResetForm
    email_template_name = 'core/password_reset_email.html'
    subject_template_name = 'core/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        email = form.cleaned_data['email']
        log_audit_event(
            None,
            "Password Reset Requested",
            f"Password reset link requested for institutional email: {email}",
            self.request
        )
        return super().form_valid(form)


class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'core/password_reset_done.html'


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'core/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def form_valid(self, form):
        user = form.user
        log_audit_event(
            user,
            "Password Reset Completed",
            f"User '{user.username}' successfully reset their account password.",
            self.request
        )
        return super().form_valid(form)


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'core/password_reset_complete.html'
