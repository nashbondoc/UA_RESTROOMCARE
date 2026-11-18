import io
from unittest.mock import patch, MagicMock
from PIL import Image
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile

from core.models import RestroomLocation, RestroomReport, UserProfile, AuditLog, SuspiciousActivityLog


def create_test_image(name='test.jpg'):
    file = io.BytesIO()
    image = Image.new('RGB', (100, 100), color=(73, 109, 137))
    image.save(file, 'jpeg')
    file.seek(0)
    return SimpleUploadedFile(name, file.read(), content_type='image/jpeg')


class UARestroomCareSystemTests(TestCase):
    def setUp(self):
        self.client = Client()

        # Stub Google's tokeninfo verification: token "g:<email>" == Google vouches for <email>.
        def fake_google(token):
            if token and token.startswith('g:'):
                return {'email': token[2:], 'email_verified': 'true', 'given_name': 'G'}
            return None
        patcher = patch('core.views.verify_google_id_token', side_effect=fake_google)
        patcher.start()
        self.addCleanup(patcher.stop)

        # Create Admin User
        self.admin_user = User.objects.create_superuser(
            username='admin_boss',
            email='admin@ua.edu.ph',
            password='Password123!'
        )
        UserProfile.objects.create(
            user=self.admin_user,
            role='admin',
            is_verified=True
        )

        # Create Active Verified Student User
        self.student_user = User.objects.create_user(
            username='student_john',
            first_name='John',
            last_name='Doe',
            email='john.doe@ua.edu.ph',
            password='Password123!'
        )
        self.student_profile = UserProfile.objects.create(
            user=self.student_user,
            role='student',
            student_id='2024-00123',
            is_verified=True
        )

        # Create Restroom Location
        self.location = RestroomLocation.objects.create(
            building='Main Academic Hall',
            floor='2nd Floor',
            room_number='MAH-204',
            gender='Female'
        )

    # -------------------------------------------------------------
    # 1. AUTHENTICATION & PORTAL ACCESS TESTS
    # -------------------------------------------------------------

    def test_admin_portal_login_success(self):
        """Admin can access dedicated admin portal and gets redirected to admin dashboard."""
        response = self.client.post(reverse('admin_login'), {
            'username': 'admin_boss',
            'password': 'Password123!'
        })
        self.assertRedirects(response, reverse('admin_dashboard'))

    def test_student_blocked_from_admin_portal(self):
        """When a student tries to log in through the Admin Portal, access is blocked and logged."""
        response = self.client.post(reverse('admin_login'), {
            'username': 'student_john',
            'password': 'Password123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Access Denied: This portal is strictly restricted")
        
        # Verify SuspiciousActivityLog entry was recorded
        self.assertTrue(
            SuspiciousActivityLog.objects.filter(
                user=self.student_user,
                reason__icontains="Blocked student attempt to login via Dedicated Admin Portal"
            ).exists()
        )

    def test_admin_blocked_from_student_portal_redirects_to_admin_portal(self):
        """When an Admin attempts to log in through the Student Portal, they are blocked and redirected to Admin Portal."""
        response = self.client.post(reverse('login'), {
            'username': 'admin_boss',
            'password': 'Password123!'
        })
        self.assertRedirects(response, reverse('admin_login'))

        follow_response = self.client.post(reverse('login'), {
            'username': 'admin_boss',
            'password': 'Password123!'
        }, follow=True)
        self.assertContains(follow_response, "Administrative accounts must log in through the official Admin Portal.")
        self.assertFalse(follow_response.wsgi_request.user.is_authenticated)

    def test_admin_blocked_from_google_student_login(self):
        """When an Admin attempts Google Sign-In on the Student Portal, they are logged out and redirected to Admin Portal."""
        response = self.client.post(reverse('google_login'), {
            'credential': 'g:' + self.admin_user.email,
            'google_first_name': 'Admin',
            'google_last_name': 'Boss'
        })
        self.assertRedirects(response, reverse('admin_login'))

        follow_response = self.client.post(reverse('google_login'), {
            'credential': 'g:' + self.admin_user.email,
            'google_first_name': 'Admin',
            'google_last_name': 'Boss'
        }, follow=True)
        self.assertContains(follow_response, "Administrative accounts must log in through the official Admin Portal.")
        self.assertFalse(follow_response.wsgi_request.user.is_authenticated)

    def test_student_login_via_main_portal_redirects_to_user_dashboard(self):
        """When Student logs in through Main Portal using @ua.edu.ph email or Student ID, redirected to user dashboard."""
        # 1. Login with @ua.edu.ph email
        response_email = self.client.post(reverse('login'), {
            'username': 'john.doe@ua.edu.ph',
            'password': 'Password123!'
        })
        self.assertRedirects(response_email, reverse('dashboard'))
        self.client.logout()

        # 2. Login with numeric Student ID (with hyphen)
        response_id = self.client.post(reverse('login'), {
            'username': '2024-00123',
            'password': 'Password123!'
        })
        self.assertRedirects(response_id, reverse('dashboard'))
        self.client.logout()

        # 3. Login with numeric Student ID (digits only)
        response_digits = self.client.post(reverse('login'), {
            'username': '202400123',
            'password': 'Password123!'
        })
        self.assertRedirects(response_digits, reverse('dashboard'))

    def test_student_login_rejects_non_email_non_numeric_username(self):
        """Main Portal rejects plain non-email usernames or non-@ua.edu.ph emails."""
        # Plain text handle rejected
        resp1 = self.client.post(reverse('login'), {
            'username': 'student_john',
            'password': 'Password123!'
        })
        self.assertEqual(resp1.status_code, 200)
        self.assertContains(resp1, "Invalid login format")
        self.assertFalse(resp1.wsgi_request.user.is_authenticated)

        # Non-UA email rejected
        resp2 = self.client.post(reverse('login'), {
            'username': 'john.doe@gmail.com',
            'password': 'Password123!'
        })
        self.assertEqual(resp2.status_code, 200)
        self.assertContains(resp2, "Invalid login format")
        self.assertFalse(resp2.wsgi_request.user.is_authenticated)

    # -------------------------------------------------------------
    # 2. STUDENT REGISTRATION, DUAL-ID (FRONT & BACK) & DUPLICATION CHECK
    # -------------------------------------------------------------

    def test_registration_requires_ua_institutional_email(self):
        """Non-@ua.edu.ph email addresses must fail validation."""
        test_front = create_test_image('front.jpg')
        test_back = create_test_image('back.jpg')
        response = self.client.post(reverse('register'), {
            'first_name': 'Alice',
            'last_name': 'Smith',
            'username': 'alice_smith',
            'email': 'alice@gmail.com',  # Invalid non-institutional email
            'student_id': '2024-99887',
            'id_picture': test_front,
            'id_picture_back': test_back,
            'password': 'SecretPassword123!',
            'confirm_password': 'SecretPassword123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "@ua.edu.ph")
        self.assertFalse(User.objects.filter(username='alice_smith').exists())

    def test_duplicate_student_id_strictly_blocked(self):
        """Once an ID's identity has been registered, that ID cannot be used to create another account."""
        test_front = create_test_image('front.jpg')
        test_back = create_test_image('back.jpg')

        # Attempt to register with existing student_id '2024-00123'
        response = self.client.post(reverse('register'), {
            'first_name': 'Imposter',
            'last_name': 'User',
            'username': 'imposter_user',
            'email': 'imposter@ua.edu.ph',
            'student_id': '2024-00123',  # Duplicate!
            'id_picture': test_front,
            'id_picture_back': test_back,
            'password': 'SecretPassword123!',
            'confirm_password': 'SecretPassword123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Duplication")
        self.assertFalse(User.objects.filter(username='imposter_user').exists())

        # Attempt with normalized format '202400123' without hyphen
        test_front2 = create_test_image('front2.jpg')
        test_back2 = create_test_image('back2.jpg')
        response2 = self.client.post(reverse('register'), {
            'first_name': 'Imposter2',
            'last_name': 'User2',
            'username': 'imposter_user2',
            'email': 'imposter2@ua.edu.ph',
            'student_id': '202400123',  # Same normalized ID!
            'id_picture': test_front2,
            'id_picture_back': test_back2,
            'password': 'SecretPassword123!',
            'confirm_password': 'SecretPassword123!'
        })
        self.assertEqual(response2.status_code, 200)
        self.assertContains(response2, "Duplication")
        self.assertFalse(User.objects.filter(username='imposter_user2').exists())

    @patch('core.views.parse_ocr_text')
    def test_registration_ocr_success_with_front_and_back_id(self, mock_ocr):
        """OCR checks back card for Student ID number and front card for student name."""
        def ocr_side_effect(image_file):
            if 'back' in getattr(image_file, 'name', ''):
                return 'official student id: 2024-11223 barcode: ||| ||||'
            return 'republic of the philippines name: maria santos program: bscs'

        mock_ocr.side_effect = ocr_side_effect

        test_front = create_test_image('front_id.jpg')
        test_back = create_test_image('back_id.jpg')

        response = self.client.post(reverse('register'), {
            'first_name': 'Maria',
            'last_name': 'Santos',
            'username': 'maria_santos',
            'email': 'maria.santos@ua.edu.ph',
            'student_id': '2024-11223',
            'id_picture': test_front,
            'id_picture_back': test_back,
            'password': 'SecretPassword123!',
            'confirm_password': 'SecretPassword123!'
        })
        self.assertRedirects(response, reverse('login'))

        user = User.objects.get(username='maria_santos')
        self.assertTrue(user.is_active)
        self.assertTrue(user.profile.is_verified)
        self.assertTrue(bool(user.profile.id_picture))
        self.assertTrue(bool(user.profile.id_picture_back))

    def test_admin_can_approve_pending_student(self):
        """Admin can approve pending student, activating the account."""
        pending_user = User.objects.create_user(
            username='pending_student',
            email='pending@ua.edu.ph',
            password='Password123!',
            is_active=False
        )
        pending_profile = UserProfile.objects.create(
            user=pending_user,
            student_id='2024-55555',
            is_verified=False
        )

        self.client.login(username='admin_boss', password='Password123!')
        get_resp = self.client.get(reverse('verify_student', args=[pending_profile.id, 'approve']))
        self.assertEqual(get_resp.status_code, 405)
        pending_profile.refresh_from_db()
        self.assertFalse(pending_profile.is_verified)
        response = self.client.post(reverse('verify_student', args=[pending_profile.id, 'approve']))
        self.assertRedirects(response, reverse('admin_verifications'))

        pending_user.refresh_from_db()
        pending_profile.refresh_from_db()
        self.assertTrue(pending_user.is_active)
        self.assertTrue(pending_profile.is_verified)

    def test_admin_can_reject_pending_student(self):
        """When Admin clicks Reject, the student registration record is permanently deleted."""
        reject_user = User.objects.create_user(
            username='reject_student',
            email='reject@ua.edu.ph',
            password='Password123!',
            is_active=False
        )
        reject_profile = UserProfile.objects.create(
            user=reject_user,
            student_id='2024-66666',
            is_verified=False
        )

        self.client.login(username='admin_boss', password='Password123!')
        response = self.client.post(reverse('verify_student', args=[reject_profile.id, 'reject']))
        self.assertRedirects(response, reverse('admin_verifications'))

        self.assertFalse(User.objects.filter(username='reject_student').exists())
        self.assertFalse(UserProfile.objects.filter(id=reject_profile.id).exists())

    # -------------------------------------------------------------
    # 3. INCIDENT REPORTING & PHOTO EVIDENCE TESTS
    # -------------------------------------------------------------

    def test_submit_report_with_photo_and_urgent_flag(self):
        """User can submit report with location, category, photo, description, and urgent flag."""
        self.client.login(username='student_john', password='Password123!')
        test_photo = create_test_image('leak.jpg')

        response = self.client.post(reverse('submit_report'), {
            'location': self.location.id,
            'category': 'Plumbing',
            'description': 'Water leaking rapidly under the 2nd sink.',
            'photo': test_photo,
            'is_urgent': True
        })
        self.assertRedirects(response, reverse('dashboard'))

        report = RestroomReport.objects.filter(user=self.student_user).first()
        self.assertIsNotNone(report)
        self.assertEqual(report.category, 'Plumbing')
        self.assertTrue(report.is_urgent)
        self.assertEqual(report.status, 'Pending')

    # -------------------------------------------------------------
    # 4. SECURITY, ANTI-SPAM & RATE LIMITING TESTS
    # -------------------------------------------------------------

    def test_duplicate_report_blocked(self):
        """If an active report exists for same location & category, submission is blocked and logged."""
        # Create existing active report
        existing_report = RestroomReport.objects.create(
            user=self.admin_user,
            location=self.location,
            category='Cleanliness',
            description='Floor is dirty.',
            status='In Progress'
        )

        self.client.login(username='student_john', password='Password123!')
        test_photo = create_test_image('mess.jpg')

        response = self.client.post(reverse('submit_report'), {
            'location': self.location.id,
            'category': 'Cleanliness',
            'description': 'Attempting duplicate submission.',
            'photo': test_photo,
            'is_urgent': False
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Duplicate Report Blocked")

        # Verify SuspiciousActivityLog entry
        self.assertTrue(
            SuspiciousActivityLog.objects.filter(
                user=self.student_user,
                reason__icontains="Duplicate report attempted"
            ).exists()
        )

    def test_hourly_rate_limiting_enforced(self):
        """Submitting beyond hourly limit blocks user and records in SuspiciousActivityLog."""
        self.client.login(username='student_john', password='Password123!')

        # Create 3 recent reports for this user
        loc2 = RestroomLocation.objects.create(building='Library', floor='1', room_number='L-101', gender='Male')
        loc3 = RestroomLocation.objects.create(building='Gym', floor='1', room_number='G-102', gender='Male')
        loc4 = RestroomLocation.objects.create(building='Chapel', floor='1', room_number='C-103', gender='Male')

        RestroomReport.objects.create(user=self.student_user, location=loc2, category='Plumbing', description='1')
        RestroomReport.objects.create(user=self.student_user, location=loc3, category='Supplies', description='2')
        RestroomReport.objects.create(user=self.student_user, location=loc4, category='Damaged Fixtures', description='3')

        # 4th submission within 1 hour
        test_photo = create_test_image('4th.jpg')
        response = self.client.post(reverse('submit_report'), {
            'location': self.location.id,
            'category': 'Other',
            'description': 'Spam attempt report',
            'photo': test_photo,
            'is_urgent': False
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Rate Limit Exceeded")

        # Verify SuspiciousActivityLog
        self.assertTrue(
            SuspiciousActivityLog.objects.filter(
                user=self.student_user,
                reason__icontains="Hourly submission limit exceeded"
            ).exists()
        )

    # -------------------------------------------------------------
    # 5. MAINTENANCE MANAGEMENT & ADMINISTRATION TESTS
    # -------------------------------------------------------------

    def test_admin_update_status_with_notes(self):
        """Admin can update report status to Resolved and attach resolution notes."""
        report = RestroomReport.objects.create(
            user=self.student_user,
            location=self.location,
            category='Plumbing',
            description='Pipe leaking.',
            status='Pending'
        )

        self.client.login(username='admin_boss', password='Password123!')
        response = self.client.post(reverse('update_status', args=[report.id]), {
            'status': 'Resolved',
            'resolution_notes': 'Maintenance team replaced the washer valve at 2:30 PM.'
        })
        self.assertRedirects(response, reverse('admin_dashboard'))

        report.refresh_from_db()
        self.assertEqual(report.status, 'Resolved')
        self.assertEqual(report.resolution_notes, 'Maintenance team replaced the washer valve at 2:30 PM.')

        # Verify AuditLog created
        self.assertTrue(
            AuditLog.objects.filter(
                actor=self.admin_user,
                action="Report Status Update"
            ).exists()
        )

    def test_admin_navigation_control_center_verifications_audit_logs_stays_authenticated(self):
        """Admin navigating across Control Center, Verifications, and Audit Logs remains authenticated without session logout."""
        login_resp = self.client.post(reverse('admin_login'), {
            'username': 'admin_boss',
            'password': 'Password123!'
        })
        self.assertRedirects(login_resp, reverse('admin_dashboard'))

        # 1. Access Admin Control Center
        dashboard_resp = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(dashboard_resp.status_code, 200)
        self.assertContains(dashboard_resp, "Restroom Operations Command")
        self.assertTrue(dashboard_resp.wsgi_request.user.is_authenticated)

        # 2. Access Verifications Portal
        verif_resp = self.client.get(reverse('admin_verifications'))
        self.assertEqual(verif_resp.status_code, 200)
        self.assertContains(verif_resp, "Student Identity Verifications")
        self.assertTrue(verif_resp.wsgi_request.user.is_authenticated)

        # 3. Access Audit Logs
        audit_resp = self.client.get(reverse('audit_logs'))
        self.assertEqual(audit_resp.status_code, 200)
        self.assertContains(audit_resp, "System Audit Trail")
        self.assertTrue(audit_resp.wsgi_request.user.is_authenticated)

    def test_admin_verifications_rbac(self):
        """Non-admin student cannot access verifications portal; unauthenticated user is redirected to login."""
        # Unauthenticated access
        unauth_resp = self.client.get(reverse('admin_verifications'))
        self.assertRedirects(unauth_resp, f"{reverse('login')}?next={reverse('admin_verifications')}")

        # Student access is redirected with permission error
        self.client.login(username='student_john', password='Password123!')
        student_resp = self.client.get(reverse('admin_verifications'))
        self.assertRedirects(student_resp, reverse('dashboard'))

    # -------------------------------------------------------------
    # 6. ACCOUNT RECOVERY (PASSWORD RESET) TESTS
    # -------------------------------------------------------------

    def test_password_reset_requires_ua_institutional_email(self):
        """Password reset rejects non-institutional emails and non-existing accounts."""
        response = self.client.post(reverse('password_reset'), {
            'email': 'hacker@external.com'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "@ua.edu.ph")

    # -------------------------------------------------------------
    # 7. GOOGLE SSO & INSTITUTIONAL DOMAIN VALIDATION TESTS
    # -------------------------------------------------------------

    def test_google_login_rejects_non_ua_domain(self):
        """Google sign-in strictly blocks non-@ua.edu.ph accounts and logs suspicious activity."""
        response = self.client.post(reverse('google_login'), {
            'credential': 'g:' + 'intruder@gmail.com',
            'google_first_name': 'External'
        })
        self.assertRedirects(response, reverse('login'))
        
        # Verify error message was delivered
        response_follow = self.client.post(reverse('google_login'), {
            'credential': 'g:' + 'intruder@gmail.com',
            'google_first_name': 'External'
        }, follow=True)
        self.assertContains(response_follow, "Access Restricted")
        self.assertContains(response_follow, "@ua.edu.ph")

        # Verify SuspiciousActivityLog entry
        self.assertTrue(
            SuspiciousActivityLog.objects.filter(
                reason__icontains="Attempted Google Sign-In with unauthorized non-institutional email 'intruder@gmail.com'"
            ).exists()
        )

    def test_google_login_unregistered_ua_redirects_to_register(self):
        """Google sign-in with unregistered @ua.edu.ph email redirects to registration with pre-filled email."""
        unregistered_email = 'newstudent@ua.edu.ph'
        response = self.client.post(reverse('google_login'), {
            'credential': 'g:' + unregistered_email,
            'google_first_name': 'New',
            'google_last_name': 'Student'
        })
        expected_url = reverse('register') + f"?email={unregistered_email}&verified=google"
        self.assertRedirects(response, expected_url)

        # Verify alert message appears on registration page
        follow_response = self.client.post(reverse('google_login'), {
            'credential': 'g:' + unregistered_email,
            'google_first_name': 'New',
            'google_last_name': 'Student'
        }, follow=True)
        self.assertContains(follow_response, "Account not registered. Please complete your registration first.")
        # Pre-filled email in the form
        self.assertContains(follow_response, unregistered_email)
        # Verified Google email is marked readonly
        self.assertContains(follow_response, 'readonly="readonly"')

    def test_google_login_allows_existing_registered_ua_student(self):
        """Google sign-in directly authenticates existing registered @ua.edu.ph accounts."""
        response = self.client.post(reverse('google_login'), {
            'credential': 'g:' + self.student_user.email,
            'google_first_name': 'Student',
            'google_last_name': 'User'
        })
        self.assertRedirects(response, reverse('dashboard'))

        # Verify user is logged in
        follow_response = self.client.get(reverse('dashboard'))
        self.assertEqual(follow_response.status_code, 200)

    def test_google_id_token_server_verification(self):
        """Only Google-verified tokens can sign in; unsigned/forged tokens and raw e-mail fields are rejected."""
        # 1. Valid registered UA student with a verified Google token
        response = self.client.post(reverse('google_login'), {'credential': 'g:' + self.student_user.email})
        self.assertRedirects(response, reverse('dashboard'))
        self.client.logout()

        # 2. Unregistered UA student -> redirect to register with locked email
        response2 = self.client.post(reverse('google_login'), {'credential': 'g:token_student@ua.edu.ph'}, follow=True)
        self.assertContains(response2, 'Account not registered. Please complete your registration first.')
        self.assertContains(response2, 'readonly="readonly"')

        # 3. Non-UA Google token -> strictly blocked
        response3 = self.client.post(reverse('google_login'), {'credential': 'g:intruder.token@gmail.com'}, follow=True)
        self.assertContains(response3, "Access Restricted")

    def test_google_login_bypass_with_raw_email_or_unsigned_token_is_rejected(self):
        """Posting a victim's e-mail or a hand-made unsigned JWT must NOT create a session."""
        import json, base64
        h = base64.urlsafe_b64encode(json.dumps({'alg': 'none'}).encode()).decode().rstrip('=')
        pl = base64.urlsafe_b64encode(json.dumps({'email': self.student_user.email}).encode()).decode().rstrip('=')
        forged = f"{h}.{pl}.sig"

        # Raw e-mail field with no token: never trusted.
        r1 = self.client.post(reverse('google_login'), {'google_email': self.student_user.email}, follow=True)
        self.assertFalse(r1.wsgi_request.user.is_authenticated)
        # Forged unsigned token: the (stubbed) Google verifier rejects anything not issued by Google.
        r2 = self.client.post(reverse('google_login'), {'credential': forged}, follow=True)
        self.assertFalse(r2.wsgi_request.user.is_authenticated)
        self.assertTrue(AuditLog.objects.filter(action='Failed Login Attempt').exists())

    def test_login_does_not_rewrite_password_hash(self):
        """Logging in must not re-hash the password (would desync sessions across serverless instances)."""
        before = User.objects.get(pk=self.admin_user.pk).password
        self.client.post(reverse('admin_login'), {'username': 'admin_boss', 'password': 'Password123!'})
        after = User.objects.get(pk=self.admin_user.pk).password
        self.assertEqual(before, after)
        self.assertIn('$1500000$', before)

    @patch('core.views.parse_ocr_text', return_value='')
    def test_registration_survives_readonly_filesystem_oserror(self, mock_ocr):
        """If file storage raises OSError (Errno 30 on serverless), registration still completes cleanly."""
        test_front = create_test_image('front_ro.jpg')
        test_back = create_test_image('back_ro.jpg')

        original_create = UserProfile.objects.create
        call_count = {'n': 0}

        def create_with_first_oserror(**kwargs):
            call_count['n'] += 1
            if call_count['n'] == 1 and ('id_picture' in kwargs or 'id_picture_back' in kwargs):
                raise OSError(30, "Read-only file system", "/var/task/media/student_ids")
            return original_create(**kwargs)

        with patch.object(UserProfile.objects, 'create', side_effect=create_with_first_oserror):
            response = self.client.post(reverse('register'), {
                'first_name': 'Carlo',
                'last_name': 'Dizon',
                'username': 'carlo_dizon',
                'email': 'carlo.dizon@ua.edu.ph',
                'student_id': '2024990011',
                'id_picture': test_front,
                'id_picture_back': test_back,
                'password': 'SecretPassword123!',
                'confirm_password': 'SecretPassword123!'
            })

        self.assertRedirects(response, reverse('login'))
        self.assertTrue(User.objects.filter(username='carlo_dizon').exists())
        self.assertTrue(UserProfile.objects.filter(student_id='2024990011').exists())


    # -------------------------------------------------------------
    # 8. LOGIN HARDENING, AUDIT TRAIL & SESSION STABILITY
    # -------------------------------------------------------------

    def _make_student(self, username, student_id, role='student', verified=True, active=True):
        user = User.objects.create_user(
            username=username, email=f'{username}@ua.edu.ph', password='Password123!', is_active=active
        )
        UserProfile.objects.create(user=user, role=role, student_id=student_id, is_verified=verified)
        return user

    def test_unregistered_identifier_and_wrong_password_rejected(self):
        before_users = User.objects.count()
        r1 = self.client.post(reverse('login'), {'username': 'ghost@ua.edu.ph', 'password': 'Password123!'})
        self.assertEqual(r1.status_code, 200)
        self.assertFalse(r1.wsgi_request.user.is_authenticated)
        r2 = self.client.post(reverse('login'), {'username': '2099999999', 'password': 'Password123!'})
        self.assertFalse(r2.wsgi_request.user.is_authenticated)
        r3 = self.client.post(reverse('login'), {'username': 'john.doe@ua.edu.ph', 'password': 'WrongPass!'})
        self.assertEqual(r3.status_code, 200)
        self.assertFalse(r3.wsgi_request.user.is_authenticated)
        self.assertEqual(User.objects.count(), before_users)  # nothing auto-created
        self.assertEqual(AuditLog.objects.filter(action='Failed Login Attempt').count(), 3)

    def test_unverified_or_inactive_student_and_professor_cannot_login(self):
        self._make_student('pending_stu', '2025000001', verified=False, active=True)
        self._make_student('pending_prof', '2025000002', role='professor', verified=False, active=True)
        self._make_student('inactive_stu', '2025000003', verified=True, active=False)
        for ident in ('pending_stu@ua.edu.ph', 'pending_prof@ua.edu.ph', '2025000003'):
            resp = self.client.post(reverse('login'), {'username': ident, 'password': 'Password123!'})
            self.assertEqual(resp.status_code, 200, ident)
            self.assertFalse(resp.wsgi_request.user.is_authenticated, ident)
            self.assertContains(resp, 'pending administrative verification')
        # A verified professor is allowed in.
        self._make_student('ok_prof', '2025000004', role='professor', verified=True)
        resp = self.client.post(reverse('login'), {'username': 'ok_prof@ua.edu.ph', 'password': 'Password123!'})
        self.assertRedirects(resp, reverse('dashboard'))

    def test_google_login_requires_verified_profile(self):
        self._make_student('g_pending', '2025000005', verified=False, active=True)
        resp = self.client.post(reverse('google_login'), {'credential': 'g:g_pending@ua.edu.ph'}, follow=True)
        self.assertFalse(resp.wsgi_request.user.is_authenticated)

    def test_all_dashboards_require_login(self):
        for name in ('dashboard', 'submit_report', 'admin_dashboard', 'admin_verifications', 'audit_logs'):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 302, name)
            self.assertIn(reverse('login'), resp.url, name)

    def test_audit_log_records_sign_in_failed_and_sign_out_with_role(self):
        # Failed (anonymous, unknown account)
        self.client.post(reverse('login'), {'username': 'nobody@ua.edu.ph', 'password': 'x'})
        # Successful student sign-in then sign-out
        self.client.post(reverse('login'), {'username': 'john.doe@ua.edu.ph', 'password': 'Password123!'})
        self.client.get(reverse('logout'))
        # Admin sign-in
        self.client.post(reverse('admin_login'), {'username': 'admin_boss', 'password': 'Password123!'})

        failed = AuditLog.objects.get(action='Failed Login Attempt')
        self.assertEqual(failed.logged_username, 'nobody@ua.edu.ph')
        self.assertEqual(failed.logged_role, 'unregistered')
        self.assertIsNotNone(failed.timestamp)

        sign_in = AuditLog.objects.filter(action='Successful Sign-In', actor=self.student_user).get()
        self.assertEqual(sign_in.logged_username, 'student_john')
        self.assertEqual(sign_in.logged_role, 'student')

        sign_out = AuditLog.objects.get(action='Sign-Out')
        self.assertEqual(sign_out.actor, self.student_user)
        self.assertEqual(sign_out.logged_username, 'student_john')
        self.assertEqual(sign_out.logged_role, 'student')

        admin_in = AuditLog.objects.filter(action='Successful Sign-In', actor=self.admin_user).get()
        self.assertEqual(admin_in.logged_role, 'admin')

    def test_audit_logs_page_lists_newest_first_with_username_and_role(self):
        self.client.post(reverse('login'), {'username': 'older@ua.edu.ph', 'password': 'x'})
        self.client.post(reverse('login'), {'username': 'newer@ua.edu.ph', 'password': 'x'})
        self.client.post(reverse('admin_login'), {'username': 'admin_boss', 'password': 'Password123!'})
        resp = self.client.get(reverse('audit_logs'))
        self.assertEqual(resp.status_code, 200)
        content = resp.content.decode()
        self.assertLess(content.index('newer@ua.edu.ph'), content.index('older@ua.edu.ph'))
        self.assertContains(resp, 'unregistered')
        self.assertContains(resp, 'Successful Sign-In')
        logs = list(resp.context['logs'])
        self.assertEqual(logs, sorted(logs, key=lambda l: (l.timestamp, l.id), reverse=True))

    def test_admin_session_survives_switching_between_all_admin_pages(self):
        self.client.post(reverse('admin_login'), {'username': 'admin_boss', 'password': 'Password123!'})
        sequence = ['admin_dashboard', 'admin_verifications', 'audit_logs'] * 4
        for name in sequence:
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 200, name)
            self.assertTrue(resp.wsgi_request.user.is_authenticated, name)
        # POST actions in between keep the session too.
        report = RestroomReport.objects.create(
            user=self.student_user, location=self.location, category='Plumbing', description='x'
        )
        resp = self.client.post(reverse('update_status', args=[report.id]), {'status': 'In Progress'}, follow=True)
        self.assertTrue(resp.wsgi_request.user.is_authenticated)
        resp = self.client.get(reverse('audit_logs'))
        self.assertEqual(resp.status_code, 200)


class GoogleTokenVerifierTests(TestCase):
    """verify_google_id_token must never trust an unsigned/forged token."""

    def test_unsigned_token_rejected_without_google_confirmation(self):
        import json, base64
        from django.test import override_settings
        from core.views import verify_google_id_token
        h = base64.urlsafe_b64encode(json.dumps({'alg': 'none'}).encode()).decode().rstrip('=')
        pl = base64.urlsafe_b64encode(json.dumps({'email': 'a@ua.edu.ph'}).encode()).decode().rstrip('=')
        forged = f"{h}.{pl}.sig"
        with override_settings(GOOGLE_CLIENT_ID='cid'):
            with patch('core.views.requests.get', side_effect=Exception('offline')):
                self.assertIsNone(verify_google_id_token(forged))
            bad = MagicMock(status_code=400)
            with patch('core.views.requests.get', return_value=bad):
                self.assertIsNone(verify_google_id_token(forged))
            wrong_aud = MagicMock(status_code=200)
            wrong_aud.json.return_value = {'email': 'a@ua.edu.ph', 'aud': 'other', 'email_verified': 'true'}
            with patch('core.views.requests.get', return_value=wrong_aud):
                self.assertIsNone(verify_google_id_token(forged))
            good = MagicMock(status_code=200)
            good.json.return_value = {'email': 'a@ua.edu.ph', 'aud': 'cid', 'email_verified': 'true'}
            with patch('core.views.requests.get', return_value=good):
                self.assertEqual(verify_google_id_token(forged)['email'], 'a@ua.edu.ph')
        with override_settings(GOOGLE_CLIENT_ID=''):
            self.assertIsNone(verify_google_id_token(forged))
