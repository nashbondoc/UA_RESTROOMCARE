import requests
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from .models import RestroomReport, RestroomLocation, AuditLog, SuspiciousActivityLog, UserProfile
from .forms import RestroomReportForm, StudentRegistrationForm
from .utils import check_rate_limit_and_duplicates, log_audit_event


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = StudentRegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_id = request.FILES.get('id_picture')
            input_student_id = form.cleaned_data['student_id'].strip()
            input_last_name = form.cleaned_data['last_name'].strip().lower()

            is_auto_verified = False
            is_active_status = False

            # --- SAFE CLOUD OCR API VERIFICATION ---
            try:
                payload = {
                    'apikey': 'helloworld',  # Free testing API key for OCR.space
                    'language': 'eng',
                    'isOverlayRequired': False
                }
                
                # Reset file pointer and prepare byte payload
                uploaded_id.seek(0)
                files = {'file': (uploaded_id.name, uploaded_id.read(), uploaded_id.content_type)}
                
                response = requests.post('https://api.ocr.space/parse/image', files=files, data=payload, timeout=10)
                result = response.json()

                if result.get('ParsedResults'):
                    extracted_text = result['ParsedResults'][0].get('ParsedText', '').lower()

                    # Match student ID and last name against extracted image text
                    id_found = input_student_id.lower() in extracted_text
                    name_found = input_last_name in extracted_text

                    if id_found and name_found:
                        is_auto_verified = True
                        is_active_status = True
                        msg = "Registration successful! Your Student ID was automatically verified. You can now log in."
                    else:
                        msg = "Registration submitted! Automatic ID verification could not match details clearly. Pending admin approval."
                else:
                    msg = "Registration submitted! Pending admin approval."

            except Exception as e:
                # Fallback to manual review if API or network fails
                msg = "Registration submitted! Pending admin approval."

            # Reset image file pointer before saving to database
            uploaded_id.seek(0)

            # --- SAVE USER ACCOUNT & PROFILE ---
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.is_active = is_active_status
            user.save()

            UserProfile.objects.create(
                user=user,
                role='student',
                student_id=input_student_id,
                id_picture=uploaded_id,
                is_verified=is_auto_verified
            )

            log_audit_event(
                user, 
                "User Registration Submitted", 
                f"Auto Verified: {is_auto_verified} | Student ID: {input_student_id}", 
                request
            )
            messages.success(request, msg)
            return redirect('login')
    else:
        form = StudentRegistrationForm()

    return render(request, 'core/register.html', {'form': form})


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
            messages.error(request, "Invalid credentials or your account is pending admin verification.")
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
    
    # List pending student accounts waiting for approval
    pending_students = UserProfile.objects.filter(is_verified=False, role='student').select_related('user')

    stats = {
        'total': reports.count(),
        'pending': reports.filter(status='Pending').count(),
        'under_review': reports.filter(status='Under Review').count(),
        'in_progress': reports.filter(status='In Progress').count(),
        'resolved': reports.filter(status='Resolved').count(),
        'suspicious': SuspiciousActivityLog.objects.filter(reviewed=False).count(),
        'pending_registrations': pending_students.count()
    }
    suspicious_logs = SuspiciousActivityLog.objects.filter(reviewed=False)

    return render(request, 'core/admin_dashboard.html', {
        'reports': reports,
        'stats': stats,
        'suspicious_logs': suspicious_logs,
        'pending_students': pending_students
    })


@login_required
def verify_student(request, profile_id, action):
    # Admin RBAC Check
    profile = getattr(request.user, 'profile', None)
    if not profile or profile.role != 'admin':
        messages.error(request, "Access Denied.")
        return redirect('dashboard')

    target_profile = get_object_or_404(UserProfile, id=profile_id)

    if action == 'approve':
        target_profile.is_verified = True
        target_profile.user.is_active = True
        target_profile.user.save()
        target_profile.save()
        
        log_audit_event(request.user, "Student Approved", f"Approved student: {target_profile.user.username} ({target_profile.student_id})", request)
        messages.success(request, f"Student {target_profile.user.username} approved successfully!")
    
    elif action == 'reject':
        user = target_profile.user
        log_audit_event(request.user, "Student Registration Rejected", f"Rejected student: {user.username}", request)
        user.delete()  # Remove account record if ID is rejected
        messages.warning(request, "Student registration rejected and account deleted.")

    return redirect('admin_dashboard')


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
        if rejection_reason:
            report.rejection_reason = rejection_reason
        report.save()

        log_audit_event(
            request.user, 
            "Updated Report Status", 
            f"Report #{report.id} changed from {old_status} to {new_status}", 
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