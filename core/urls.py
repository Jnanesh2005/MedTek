from django.urls import path
from . import views

urlpatterns = [    
    path('', views.home, name='home'),
    path('login-options/', views.login_options, name='login'), # We will keep this for now

    path('register/', views.register_options, name='register'), # New gateway view
    path('login/', views.login_options, name='login'), # New gateway view
    path('admin-login/', views.admin_login, name='admin_login'),
    path('admin-register/', views.admin_register, name='admin_register'),
    path('student-register/', views.register, name='student_register'), # Old register view
    path('student-login/', views.login_view, name='student_login'), # Old login view
    path('otp/', views.otp_verification, name='otp_verification'),
    path('profile-setup/', views.profile_setup, name='profile_setup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submit-vitals/', views.vitals_form, name='vitals_form'),
    path('result/<int:vitals_id>/', views.result, name='result'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('google-fit/auth/', views.google_fit_auth, name='google_fit_auth'),
    path('google-fit/callback/', views.google_fit_callback, name='google_fit_callback'),
    path('sync-vitals/', views.fetch_google_fit_data, name='fetch_google_fit_data'),
    path('about/', views.about, name='about'),


]
