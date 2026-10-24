from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submit/', views.submit_report, name='submit_report'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('verify-student/<int:profile_id>/<str:action>/', views.verify_student, name='verify_student'),
    path('update-status/<int:report_id>/', views.update_report_status, name='update_status'),
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),

    # Password Reset Routes
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(template_name='core/password_reset.html'), 
         name='password_reset'),
    path('password-reset/done/', 
         auth_views.PasswordResetDoneView.as_view(template_name='core/password_reset_done.html'), 
         name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', 
         auth_views.PasswordResetConfirmView.as_view(template_name='core/password_reset_confirm.html'), 
         name='password_reset_confirm'),
    path('password-reset-complete/', 
         auth_views.PasswordResetCompleteView.as_view(template_name='core/password_reset_complete.html'), 
         name='password_reset_complete'),
]