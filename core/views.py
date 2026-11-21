import re
import json
import base64
import requests
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseNotAllowed, HttpResponse, FileResponse, Http404
from django.utils._os import safe_join
from django.core.exceptions import SuspiciousFileOperation
from django.utils.http import url_has_allowed_host_and_scheme
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

from .models import RestroomReport, RestroomLocation, AuditLog, SuspiciousActivityLog, UserProfile, StoredFile
from .forms import RestroomReportForm, StudentRegistrationForm, InstitutionalPasswordResetForm
from .utils import check_rate_limit_and_duplicates, log_audit_event, get_client_ip, get_user_role


def is_admin(user):
    """Check if the user has administrative privileges."""
    if not user or not user.is_authenticated:
        return False
    if user.is_superuser or user.is_staff:
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.role == 'admin')


def protected_media(request, path):
    """Serve uploaded files stored in the database (StoredFile model).

    ID card photos and incident report photos are persisted in PostgreSQL via
    core.storage.DatabaseStorage so they survive Vercel cold-starts and ephemeral
    filesystem resets. This view retrieves a row by its path name and streams the
    binary content back with the correct MIME type.
    """
    clean_path = path.strip('/')
    try:
        stored = StoredFile.objects.get(name=clean_path)
    except StoredFile.DoesNotExist:
        raise Http404
    return HttpResponse(bytes(stored.content), content_type=stored.content_type)


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
            timeout=4
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

PENDING_MSG = (
    "Your account registration is currently pending administrative verification. "
    "You will be granted access once your student ID has been confirmed."
)


def _resolve_portal_user(identifier):
    """Find the REGISTERED account for an @ua.edu.ph email or numeric Student ID.
    Never creates accounts; returns None when nothing is registered."""
    is_ua_email = bool(re.match(r'^[a-zA-Z0-9._%+\-]+@ua\.edu\.ph$', identifier, re.IGNORECASE))
    if is_ua_email:
        return User.objects.filter(email__iexact=identifier).first()
    clean_target = re.sub(r'[^0-9]', '', identifier)
    if not clean_target:
        return None
    for profile in UserProfile.objects.select_related('user').exclude(student_id__isnull=True):
        if profile.student_id and re.sub(r'[^0-9]', '', profile.student_id) == clean_target:
            return profile.user
    return None


def _is_verified_for_portal(user):
    """Admins skip ID verification; student/professor need profile.is_verified == True."""
    if is_admin(user):
        return True
    profile = getattr(user, 'profile', None)
    return bool(profile and profile.is_verified)


def _log_failed_login(request, identifier, reason, user=None):
    log_audit_event(
        None,
        "Failed Login Attempt",
        f"Identifier '{identifier}' rejected: {reason}.",
        request,
        username=identifier or 'anonymous',
        role=get_user_role(user) if user else 'unregistered',
    )


def login_view(request):
    """
    Main Student / Faculty Login Portal.
    - Credentials are checked only with django.contrib.auth.authenticate() against registered accounts.
    - Unregistered identifiers and wrong passwords are rejected immediately (no fallback / auto-create).
    - Non-admin roles must be is_active AND profile.is_verified before login() is called.
    - Admin accounts are bounced to the Admin Portal.
    """
    if request.user.is_authenticated:
        if is_admin(request.user):
            return redirect('admin_dashboard')
        return redirect('dashboard')

    if request.method != 'POST':
        return render(request, 'core/login.html', {'form': AuthenticationForm()})

    form = AuthenticationForm(request, data=request.POST)
    identifier = request.POST.get('username', '').strip()
    password = request.POST.get('password', '')
    ctx = {'form': form, 'entered_username': identifier}

    # Admin usernames are not valid student identifiers: detect correct admin credentials first.
    admin_candidate = User.objects.filter(
        Q(username__iexact=identifier) | Q(email__iexact=identifier)
    ).first()
    if admin_candidate and is_admin(admin_candidate):
        if authenticate(request, username=admin_candidate.get_username(), password=password) is not None:
            log_audit_event(
                admin_candidate,
                "Blocked Admin Login (Student Portal)",
                "Admin account attempted to authenticate via Student Portal and was redirected to Admin Portal.",
                request
            )
            messages.error(
                request,
                "Access Denied: Administrative accounts must log in through the official Admin Portal."
            )
            return redirect('admin_login')

    # Strict identifier format: only a valid @ua.edu.ph email or numeric Student ID
    is_ua_email = bool(re.match(r'^[a-zA-Z0-9._%+\-]+@ua\.edu\.ph$', identifier, re.IGNORECASE))
    is_numeric_id = bool(re.match(r'^[0-9][0-9\-]*$', identifier)) and any(c.isdigit() for c in identifier)
    if not (is_ua_email or is_numeric_id):
        messages.error(
            request,
            "Invalid login format: Please enter a valid @ua.edu.ph institutional email or your numeric Student ID."
        )
        _log_failed_login(request, identifier, "invalid identifier format")
        return render(request, 'core/login.html', ctx)

    resolved_user = _resolve_portal_user(identifier)
    if resolved_user is None:
        messages.error(request, "Invalid @ua.edu.ph email, Student ID, or password. Please verify your credentials.")
        _log_failed_login(request, identifier, "no registered account")
        return render(request, 'core/login.html', ctx)

    user = authenticate(request, username=resolved_user.get_username(), password=password)
    if user is None:
        if not resolved_user.is_active and resolved_user.check_password(password):
            # Correct password, but the account is still awaiting admin verification.
            messages.warning(request, PENDING_MSG)
            _log_failed_login(request, identifier, "account pending verification (inactive)", resolved_user)
        else:
            messages.error(request, "Invalid @ua.edu.ph email, Student ID, or password. Please verify your credentials.")
            _log_failed_login(request, identifier, "wrong password", resolved_user)
        return render(request, 'core/login.html', ctx)

    if not user.is_active or not _is_verified_for_portal(user):
        messages.warning(request, PENDING_MSG)
        _log_failed_login(request, identifier, "account not verified", user)
        return render(request, 'core/login.html', ctx)

    login(request, user)
    log_audit_event(user, "Successful Sign-In", "Authenticated via Main Portal.", request)
    messages.success(request, f"Welcome back, {user.get_full_name() or user.username}!")
    return redirect('dashboard')


from django.views.decorators.csrf import csrf_exempt

def verify_google_id_token(id_token):
    """
    Verifies a Google ID token with Google's tokeninfo endpoint ONLY.
    There is deliberately no offline/unsigned fallback: a forged or unsigned token must fail.
    The token's audience must equal GOOGLE_CLIENT_ID and the e-mail must be verified by Google.
    Returns the claims dict, or None if invalid.
    """
    client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '')
    if not id_token or not client_id:
        return None
    try:
        resp = requests.get(
            'https://oauth2.googleapis.com/tokeninfo',
            params={'id_token': id_token},
            timeout=5
        )
        if resp.status_code != 200:
            return None
        claims = resp.json()
    except Exception:
        return None

    if claims.get('aud') != client_id:
        return None
    if str(claims.get('email_verified', '')).lower() != 'true':
        return None
    return claims


@csrf_exempt
def google_login_view(request):
    """
    Handle Google Sign-In with strict @ua.edu.ph institutional domain validation.
    Accepts direct Google credential / ID token (server-verified) or fallback form fields.
    Non-UA accounts are rejected with an explicit error message and security logging.
    """
    if request.method != 'POST':
        return redirect('login')

    email = ''
    first_name = ''
    last_name = ''

    # 1. Check for Google ID Token (from One Tap, Google Sign-In button, or direct OAuth redirect)
    id_token = request.POST.get('credential') or request.POST.get('id_token')
    if id_token:
        token_data = verify_google_id_token(id_token)
        if token_data and 'email' in token_data:
            email = token_data.get('email', '').strip().lower()
            first_name = token_data.get('given_name') or token_data.get('name', '').split(' ')[0]
            last_name = token_data.get('family_name') or ''
        else:
            messages.error(request, "Google authentication verification failed: Invalid identity token.")
            return redirect('login')

    # No fallback to client-supplied form fields: an e-mail address that Google has not
    # vouched for (signed token) must never be able to start a session.
    if not email:
        messages.error(request, "Google authentication failed: a verified Google sign-in is required.")
        _log_failed_login(request, request.POST.get('google_email', '').strip() or 'anonymous',
                          "Google sign-in attempted without a verified Google token")
        return redirect('login')

    # Strict backend validation: only @ua.edu.ph allowed across all devices
    if not email.endswith('@ua.edu.ph'):
        log_audit_event(
            None,
            "Blocked Non-UA Google Login Attempt",
            f"Unauthorized domain sign-in attempt with email '{email}'. Only @ua.edu.ph is permitted.",
            request
        )
        SuspiciousActivityLog.objects.create(
            user=None,
            reason=f"Attempted Google Sign-In with unauthorized non-institutional email '{email}'.",
            ip_address=get_client_ip(request)
        )
        messages.error(
            request,
            f"Access Restricted: '{email}' is not an authorized University of the Assumption account. "
            "Google Sign-In is strictly restricted to official @ua.edu.ph student and faculty emails."
        )
        return redirect('login')

    # User has valid @ua.edu.ph domain
    username_candidate = email.split('@')[0]
    user = User.objects.filter(Q(email__iexact=email) | Q(username__iexact=username_candidate)).first()

    # If user does not exist, do NOT auto-provision. Redirect to registration with locked verified email.
    if not user:
        from django.urls import reverse
        request.session['google_verified_email'] = email
        register_url = reverse('register') + f"?email={email}&verified=google"
        messages.error(
            request,
            "Account not registered. Please complete your registration first."
        )
        _log_failed_login(request, email, "Google account not registered")
        return redirect(register_url)

    if not (user.is_staff or user.is_superuser or is_admin(user)) and (not user.is_active or not _is_verified_for_portal(user)):
        messages.warning(request, PENDING_MSG)
        _log_failed_login(request, email, "Google account not verified / inactive", user)
        return redirect('login')

    if user.is_staff or user.is_superuser or is_admin(user):
        logout(request)
        log_audit_event(
            user,
            "Blocked Admin Google SSO Login (Student Portal)",
            "Administrator attempted to authenticate via Student Google SSO and was redirected to Admin Portal.",
            request
        )
        messages.error(
            request,
            "Access Denied: Administrative accounts must log in through the official Admin Portal."
        )
        return redirect('admin_login')

    login(request, user)
    log_audit_event(user, "Successful Sign-In", "Student/Faculty authenticated via Google SSO.", request)
    messages.success(request, f"Welcome, {user.get_full_name() or user.username}! Successfully signed in with UA Google Account.")
    return redirect('dashboard')


def admin_login_view(request):
    """
    Dedicated Admin Portal (/admin-portal/login/).
    - Uses authenticate(); only active admin accounts are signed in.
    - Student/Faculty credentials are blocked and flagged.
    """
    if request.user.is_authenticated:
        if is_admin(request.user):
            return redirect('admin_dashboard')
        messages.error(request, "Access Denied: This portal is strictly restricted to administrative personnel.")
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        candidate = User.objects.filter(username__iexact=username).first()
        user = authenticate(request, username=candidate.get_username(), password=password) if candidate else None

        if user is not None:
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

            login(request, user)
            log_audit_event(
                user,
                "Successful Sign-In",
                "Administrator successfully authenticated through Dedicated Admin Portal.",
                request
            )
            messages.success(request, f"Welcome to the Admin Control Center, {user.get_full_name() or user.username}!")
            return redirect('admin_dashboard')

        if candidate and is_admin(candidate) and not candidate.is_active and candidate.check_password(password):
            messages.error(request, "Your administrative account is currently deactivated. Please contact campus IT.")
            _log_failed_login(request, username, "administrative account deactivated", candidate)
            return render(request, 'core/admin_login.html', {'entered_username': username})

        messages.error(request, "Invalid administrator credentials.")
        _log_failed_login(request, username, "invalid administrator credentials (Admin Portal)", candidate)
        return render(request, 'core/admin_login.html', {'entered_username': username})

    return render(request, 'core/admin_login.html')


@login_required
def logout_view(request):
    """Sign out: capture request.user (and role) BEFORE logout() clears the session, then audit it."""
    user = request.user
    username = user.get_username()
    role = get_user_role(user)
    logout(request)
    log_audit_event(user, "Sign-Out", f"User {username} signed out safely.", request, username=username, role=role)
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

    is_google_verified = request.GET.get('verified') == 'google' or request.session.get('google_verified_email') is not None
    verified_email = request.session.get('google_verified_email') or request.GET.get('email', '').strip()
    target_email = verified_email

    if request.method == 'POST':
        target_email = verified_email or request.POST.get('email', '').strip()
        form = StudentRegistrationForm(request.POST, request.FILES, lock_email=is_google_verified)
        if form.is_valid():
            # If came from verified google oauth, clean session
            request.session.pop('google_verified_email', None)
            uploaded_front = request.FILES.get('id_picture')
            uploaded_back = request.FILES.get('id_picture_back')
            input_student_id = form.cleaned_data['student_id'].strip()
            input_first_name = form.cleaned_data['first_name'].strip()
            input_last_name = form.cleaned_data['last_name'].strip()
            input_email = form.cleaned_data['email'].strip().lower()
            chosen_role = form.cleaned_data['role']
            if chosen_role not in ('student', 'professor'):
                chosen_role = 'student'

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
                user_msg = "Identity Verified! Your ID details have been verified. You may now log in."
            elif id_matched or name_matched:
                ocr_detail = f"Partial card match (ID={id_matched}, Name={name_matched}). Sent to admin approval."
                user_msg = "Registration Received: Your identity verification is pending administrative review."
            else:
                ocr_detail = "OCR scans unclear. Sent to manual admin review."
                user_msg = "Registration Received: Your verification request has been queued for review."

            # Reset file pointers before model saving
            if uploaded_front:
                uploaded_front.seek(0)
            if uploaded_back:
                uploaded_back.seek(0)

            # Create User record
            user = form.save(commit=False)
            user.username = input_email  # institutional email is the account username
            user.set_password(form.cleaned_data['password'])
            user.is_active = is_active_status
            user.save()

            # Create UserProfile record with Front and Back ID photos
            try:
                UserProfile.objects.create(
                    user=user,
                    role=chosen_role,
                    student_id=input_student_id,
                    id_picture=uploaded_front,
                    id_picture_back=uploaded_back,
                    is_verified=is_auto_verified
                )
            except OSError:
                # Fallback if filesystem storage is read-only
                UserProfile.objects.create(
                    user=user,
                    role=chosen_role,
                    student_id=input_student_id,
                    is_verified=is_auto_verified
                )

            # Log audit event
            log_audit_event(
                user,
                "Faculty Registration Submitted" if chosen_role == 'professor' else "Student Registration Submitted",
                f"Role: {chosen_role} | ID: {input_student_id} | Verified: {is_auto_verified} | Card Scans: {ocr_detail}",
                request
            )

            if is_auto_verified:
                messages.success(request, user_msg)
            else:
                messages.info(request, user_msg)

            return redirect('login')
    else:
        initial_data = {}
        target_email = verified_email or request.GET.get('email', '').strip()
        if target_email:
            initial_data['email'] = target_email
        form = StudentRegistrationForm(initial=initial_data, lock_email=is_google_verified)

    return render(request, 'core/register.html', {
        'form': form,
        'is_google_verified': is_google_verified,
        'verified_email': target_email
    })


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
            try:
                report.save()
            except OSError:
                report.photo = None
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
    Admin Control Center:
    - Focused on KPI metrics and Incident Report Queue.
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
    pending_students_count = UserProfile.objects.filter(is_verified=False, role__in=['student', 'professor']).count()
    suspicious_logs = SuspiciousActivityLog.objects.filter(reviewed=False).order_by('-flagged_at')[:20]

    stats = {
        'total': reports.count(),
        'pending': reports.filter(status='Pending').count(),
        'under_review': reports.filter(status='Under Review').count(),
        'in_progress': reports.filter(status='In Progress').count(),
        'resolved': reports.filter(status='Resolved').count(),
        'rejected': reports.filter(status='Rejected').count(),
        'suspicious': SuspiciousActivityLog.objects.filter(reviewed=False).count(),
        'pending_registrations': pending_students_count
    }

    return render(request, 'core/admin_dashboard.html', {
        'reports': reports,
        'stats': stats,
        'suspicious_logs': suspicious_logs,
    })


@login_required
def admin_verifications_view(request):
    """
    Dedicated Student Identity Verifications Portal (/verifications/):
    - Front & Back ID Card review with Dual-ID inspection modals.
    - Approve / Reject student identity registration workflows.
    """
    if not is_admin(request.user):
        messages.error(request, "Access Denied: Administrative privileges required.")
        return redirect('dashboard')

    pending_students = UserProfile.objects.filter(is_verified=False, role__in=['student', 'professor']).select_related('user').order_by('-user__date_joined')
    return render(request, 'core/verifications.html', {
        'pending_students': pending_students,
        'pending_count': pending_students.count(),
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

    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

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

    # Redirect back to referring page (Verifications or Admin Dashboard)
    next_url = request.POST.get('next')
    if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        return redirect(next_url)
    return redirect('admin_verifications')


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
    logs_qs = AuditLog.objects.select_related('actor', 'actor__profile').order_by('-timestamp', '-id')

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
