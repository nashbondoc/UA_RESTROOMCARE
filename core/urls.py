from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),  # Root route directly loads the login page
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submit/', views.submit_report, name='submit_report'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('update-status/<int:report_id>/', views.update_report_status, name='update_status'),
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),
]