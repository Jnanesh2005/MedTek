from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('otp/', views.otp_verification, name='otp_verification'),
    path('profile-setup/', views.profile_setup, name='profile_setup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('submit-vitals/', views.vitals_form, name='submit_vitals'),
    path('result/<int:vitals_id>/', views.result, name='result'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('', views.login_view, name='home'),
]