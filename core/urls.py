from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('admin-login/', views.admin_login, name='admin_login'),
    path('admin-register/', views.admin_register, name='admin_register'),
    path('otp/', views.otp_verification, name='otp_verification'),
    path('profile-setup/', views.profile_setup, name='profile_setup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submit-vitals/', views.vitals_form, name='submit_vitals'),
    path('result/<int:vitals_id>/', views.result, name='result'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('', views.home, name='home'),
    path('google-fit/auth/', views.google_fit_auth, name='google_fit_auth'),
    path('google-fit/callback/', views.google_fit_callback, name='google_fit_callback'),
    path('sync-vitals/', views.fetch_google_fit_data, name='fetch_google_fit_data'),

]
