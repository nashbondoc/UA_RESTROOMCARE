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

    def test_admin_login_via_main_portal_redirects_to_admin_dashboard(self):
        """When an Admin logs in through the Main Portal, system automatically redirects them to Admin Dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'admin_boss',
            'password': 'Password123!'
        })
        self.assertRedirects(response, reverse('admin_dashboard'))

    def test_student_login_via_main_portal_redirects_to_user_dashboard(self):
        """When Student logs in through Main Portal, redirected to user dashboard."""
        response = self.client.post(reverse('login'), {
            'username': 'student_john',
            'password': 'Password123!'
        })
        self.assertRedirects(response, reverse('dashboard'))

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
        response = self.client.get(reverse('verify_student', args=[pending_profile.id, 'approve']))
        self.assertRedirects(response, reverse('admin_dashboard'))

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
        response = self.client.get(reverse('verify_student', args=[reject_profile.id, 'reject']))
        self.assertRedirects(response, reverse('admin_dashboard'))

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
