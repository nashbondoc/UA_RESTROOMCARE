from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import datetime

class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('student', 'Student'),
        ('professor', 'Professor/Teacher'),
        ('admin', 'Administrator/Authorized Personnel'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')
    department = models.CharField(max_length=100, blank=True, null=True)
    
    # Bagong fields para sa Student ID Verification
    student_id = models.CharField(max_length=50, blank=True, null=True, unique=True)
    id_picture = models.ImageField(upload_to='student_ids/', blank=True, null=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"


class RestroomLocation(models.Model):
    building = models.CharField(max_length=100)
    floor = models.CharField(max_length=50)
    room_number = models.CharField(max_length=50)
    gender = models.CharField(max_length=20, choices=[('Male', 'Male'), ('Female', 'Female'), ('All-Gender', 'All-Gender')])

    def __str__(self):
        return f"{self.building} Flr {self.floor} ({self.room_number}) - {self.gender}"


class RestroomReport(models.Model):
    CATEGORY_CHOICES = (
        ('cleanliness', 'Cleanliness Issue'),
        ('water_soap', 'Lack of Water / Soap'),
        ('odor', 'Unpleasant Odor'),
        ('damaged_faucet', 'Damaged Faucet / Sink'),
        ('damaged_toilet', 'Damaged Toilet / Flush'),
        ('damaged_door', 'Damaged Door / Lock'),
        ('damaged_light', 'Lighting Issue'),
        ('damaged_mirror', 'Damaged Mirror / Wall'),
        ('other', 'Other Safety or Facility Concern'),
    )

    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Under Review', 'Under Review'),
        ('Verified', 'Verified'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved'),
        ('Rejected', 'Rejected'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    location = models.ForeignKey(RestroomLocation, on_delete=models.CASCADE, related_name='reports')
    category = models.CharField(max_length=30, choices=CATEGORY_CHOICES)
    description = models.TextField()
    photo = models.ImageField(upload_to='report_photos/', blank=True, null=True)
    is_urgent = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    rejection_reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Report #{self.id} - {self.location} ({self.status})"


class AuditLog(models.Model):
    actor = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=255)
    details = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.actor}: {self.action}"


class SuspiciousActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reason = models.CharField(max_length=255)
    flagged_at = models.DateTimeField(auto_now_add=True)
    reviewed = models.BooleanField(default=False)

    def __str__(self):
        return f"Flagged User: {self.user.username} - {self.reason}"