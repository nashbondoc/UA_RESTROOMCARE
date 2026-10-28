from django.urls import path
from . import views

urlpatterns = [
    # 1. Authentication & Portal Access
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login_alias'),
    path('admin-portal/login/', views.admin_login_view, name='admin_login'),
    path('logout/', views.logout_view, name='logout'),

    # 2. Student Registration & Verification
    path('register/', views.register_view, name='register'),
    path('verify-student/<int:profile_id>/<str:action>/', views.verify_student, name='verify_student'),

    # 3. Incident Reporting
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submit/', views.submit_report, name='submit_report'),

    # 4. Maintenance Management & Administration
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('update-status/<int:report_id>/', views.update_report_status, name='update_status'),
    path('review-suspicious/<int:log_id>/', views.mark_suspicious_reviewed, name='mark_suspicious_reviewed'),
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),

    # 5. Account Recovery (Password Reset Workflow)
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset-complete/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]
