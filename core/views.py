from django.shortcuts import render

# Create your views here.
import random
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from .forms import UserRegistrationForm, OTPVerificationForm, ProfileSetupForm, VitalsSubmissionForm
from .models import GoogleFitToken, StudentProfile, VitalsSubmission, OTP
import smtplib
from email.mime.text import MIMEText
import ssl
import random
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import datetime
import json
import requests

def create_client_secrets_dict():
    """Creates a client_secrets dictionary from environment variables."""
    return {
        "web": {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }
# In core/views.py, with other helper functions
# In core/views.py, with other helper functions
def refresh_google_fit_token(token_obj):
    """
    Refreshes the Google Fit access token using the refresh token.
    """
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from google.auth.transport.requests import Request
    import requests
    import datetime

    credentials_dict = {
        'token': token_obj.access_token,
        'refresh_token': token_obj.refresh_token,
        'token_uri': token_obj.token_uri,
        'client_id': token_obj.client_id,
        'client_secret': token_obj.client_secret,
        'scopes': token_obj.scopes.split(' '),
        'expiry': token_obj.expires_in,
    }

    credentials = Credentials(**credentials_dict)

    # FIX: Check if the token is about to expire, using timezone-aware datetimes
    if credentials.expiry and (credentials.expiry - datetime.timedelta(minutes=5) < datetime.datetime.now(datetime.timezone.utc)):
        request = Request()
        credentials.refresh(request)

        # Update the token object in the database
        token_obj.access_token = credentials.token
        token_obj.expires_in = credentials.expiry
        token_obj.save()
        return token_obj
    else:
        return token_obj
def send_otp_email(email, otp):
    subject = "MedTek - Your OTP for Login"
    message = f"Hello,\n\nYour One-Time Password (OTP) for MedTek is: {otp}\n\nThis OTP is valid for 5 minutes."
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]

    try:
        # Create a non-verifying SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with smtplib.SMTP_SSL(settings.EMAIL_HOST, 465, context=context) as server:
            server.login(email_from, settings.EMAIL_HOST_PASSWORD)

            msg = MIMEText(message)
            msg['Subject'] = subject
            msg['From'] = email_from
            msg['To'] = email

            server.sendmail(email_from, recipient_list, msg.as_string())
        print(f"OTP email sent successfully to {email}")

    except Exception as e:
        print(f"Failed to send email: {e}")
        raise # Re-raise the exception to see it in Django's traceback

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            if User.objects.filter(email=email).exists():
                messages.error(request, "An account with this email already exists. Please log in.")
                return redirect('login')
            
            otp_code = str(random.randint(100000, 999999))
            OTP.objects.update_or_create(email=email, defaults={'otp': otp_code})
            send_otp_email(email, otp_code)
            request.session['email'] = email
            messages.success(request, "An OTP has been sent to your email. Please verify.")
            return redirect('otp_verification')
    else:
        form = UserRegistrationForm()
    return render(request, 'core/register.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, "No account found with this email. Please register.")
                return redirect('register')
            
            otp_code = str(random.randint(100000, 999999))
            OTP.objects.update_or_create(email=email, defaults={'otp': otp_code})
            send_otp_email(email, otp_code)
            request.session['email'] = email
            messages.success(request, "An OTP has been sent to your email. Please verify.")
            return redirect('otp_verification')
    else:
        form = UserRegistrationForm()
    return render(request, 'core/login.html', {'form': form})

def otp_verification(request):
    email = request.session.get('email')
    if not email:
        messages.error(request, "Please start the login/registration process again.")
        return redirect('login')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_entered = form.cleaned_data['otp']
            try:
                otp_obj = OTP.objects.get(email=email, otp=otp_entered)
                # You might add a timestamp check here for expiration
                otp_obj.delete()

                user, created = User.objects.get_or_create(username=email, email=email)
                login(request, user)
                
                if created or not hasattr(user, 'studentprofile'):
                    return redirect('profile_setup')
                else:
                    return redirect('dashboard')
            except OTP.DoesNotExist:
                messages.error(request, "Invalid or expired OTP.")
                return redirect('otp_verification')
    else:
        form = OTPVerificationForm()
    return render(request, 'core/otp_verification.html', {'form': form})

@login_required
def profile_setup(request):
    if hasattr(request.user, 'studentprofile'):
        return redirect('dashboard') # Already set up
    
    if request.method == 'POST':
        form = ProfileSetupForm(request.POST)
        if form.is_valid():
            profile = form.save(commit=False)
            profile.user = request.user
            profile.email = request.user.email
            profile.pre_existing_diseases = ",".join(request.POST.getlist('pre_existing_diseases'))
            profile.save()
            messages.success(request, "Profile setup complete!")
            return redirect('dashboard')
    else:
        form = ProfileSetupForm()
    return render(request, 'core/profile_setup.html', {'form': form})

@login_required
def dashboard(request):
    try:
        profile = request.user.studentprofile
    except StudentProfile.DoesNotExist:
        return redirect('profile_setup')
    
    latest_vitals = VitalsSubmission.objects.filter(student_profile=profile).order_by('-submission_date').first()
    context = {
        'profile': profile,
        'latest_vitals': latest_vitals,
    }
    return render(request, 'core/dashboard.html', context)

@login_required
def vitals_form(request):
    try:
        profile = request.user.studentprofile
    except StudentProfile.DoesNotExist:
        return redirect('profile_setup')

    if request.method == 'POST':
        form = VitalsSubmissionForm(request.POST)
        if form.is_valid():
            vitals = form.save(commit=False)
            vitals.student_profile = profile

            # Health Check Logic
            status = 'Healthy'
            if vitals.spo2 < settings.HEALTH_CHECK_RULES.get('SPO2_THRESHOLD'):
                status = 'Unhealthy'
            elif vitals.temperature > settings.HEALTH_CHECK_RULES.get('TEMP_THRESHOLD'):
                status = 'Unhealthy'
            
            vitals.health_status = status
            vitals.save()
            
            return redirect('result', vitals_id=vitals.id)
    else:
        form = VitalsSubmissionForm()
    return render(request, 'core/vitals_form.html', {'form': form})

@login_required
def result(request, vitals_id):
    vitals = VitalsSubmission.objects.get(id=vitals_id)
    return render(request, 'core/result.html', {'vitals': vitals})

def is_superuser(user):
    return user.is_superuser

@user_passes_test(is_superuser)
def admin_dashboard(request):
    students = StudentProfile.objects.all().order_by('name')
    health_status_filter = request.GET.get('health_status')

    if health_status_filter:
        if health_status_filter == 'unhealthy':
            unhealthy_students = []
            for student in students:
                latest_vitals = VitalsSubmission.objects.filter(student_profile=student).order_by('-submission_date').first()
                if latest_vitals and latest_vitals.health_status == 'Unhealthy':
                    unhealthy_students.append(student)
            students = unhealthy_students

        elif health_status_filter == 'healthy':
            healthy_students = []
            for student in students:
                latest_vitals = VitalsSubmission.objects.filter(student_profile=student).order_by('-submission_date').first()
                if latest_vitals and latest_vitals.health_status == 'Healthy':
                    healthy_students.append(student)
            students = healthy_students

    student_data = []
    for student in students:
        latest_vitals = VitalsSubmission.objects.filter(student_profile=student).order_by('-submission_date').first()
        student_data.append({
            'profile': student,
            'latest_vitals': latest_vitals
        })

    return render(request, 'core/admin_dashboard.html', {'student_data': student_data})
# In core/views.py, at the end of the file
@login_required
def google_fit_auth(request):
    # Scopes are permissions our app needs from Google
    scopes = [
        'https://www.googleapis.com/auth/fitness.activity.read',
        'https://www.googleapis.com/auth/fitness.body.read',
        'https://www.googleapis.com/auth/fitness.heart_rate.read',
    ]

    # **CORRECTED:** Use the `from_client_config` method
    client_config = create_client_secrets_dict()
    flow = Flow.from_client_config(
        client_config,
        scopes=scopes,
        redirect_uri=settings.GOOGLE_REDIRECT_URI
    )

    # Get the authorization URL to redirect the user
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the session to prevent CSRF attacks
    request.session['oauth_state'] = state
    return redirect(authorization_url)


# In core/views.py
# In core/views.py
# In core/views.py
@login_required
def google_fit_callback(request):
    try:
        state = request.session.get('oauth_state')
        if not state:
            messages.error(request, "OAuth state not found in session. Please try connecting again.")
            return redirect('dashboard')

        client_config = create_client_secrets_dict()
        flow = Flow.from_client_config(
            client_config,
            scopes=None,
            state=state,
            redirect_uri=settings.GOOGLE_REDIRECT_URI
        )

        flow.fetch_token(authorization_response=request.build_absolute_uri())

        credentials = flow.credentials

        # A more robust check for scopes
        scopes_str = ''
        if credentials.scopes:
            if isinstance(credentials.scopes, str):
                scopes_str = credentials.scopes
            else:
                scopes_str = ' '.join(credentials.scopes)

        GoogleFitToken.objects.update_or_create(
            user=request.user,
            defaults={
                'access_token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'scopes': scopes_str,
                'expires_in': credentials.expiry,
            }
        )
        messages.success(request, "Google Fit connected successfully!")
        return redirect('dashboard')
    
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {e}")
        return redirect('dashboard')
# In core/views.py
@login_required
def fetch_google_fit_data(request):
    try:
        token_obj = GoogleFitToken.objects.get(user=request.user)
        token_obj = refresh_google_fit_token(token_obj)

        headers = {'Authorization': f'Bearer {token_obj.access_token}'}

        now = datetime.datetime.now(datetime.timezone.utc)
        end_time_millis = int(now.timestamp() * 1000)
        start_time_millis = int((now - datetime.timedelta(days=1)).timestamp() * 1000)

        api_url = "https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate"

        request_body = {
            "aggregateBy": [{
                "dataTypeName": "com.google.heart_rate.bpm",
                "dataSourceId": "derived:com.google.heart_rate.bpm:com.google.android.gms:merged"
            }],
            "bucketByTime": {"durationMillis": 86400000},
            "startTimeMillis": start_time_millis,
            "endTimeMillis": end_time_millis
        }

        response = requests.post(api_url, headers=headers, json=request_body)

        # Print the raw API response to the logs
        print(f"API Request URL: {api_url}")
        print(f"API Request Headers: {headers}")
        print(f"API Request Body: {json.dumps(request_body)}")
        print(f"API Response Status: {response.status_code}")
        print(f"API Response JSON: {response.text}")

        response.raise_for_status()

        data = response.json()

        heart_rate = None
        if data.get('bucket') and data['bucket'][0].get('dataset') and data['bucket'][0]['dataset'][0].get('point'):
            points = data['bucket'][0]['dataset'][0]['point']
            if points:
                heart_rates = [p['value'][0]['fpVal'] for p in points]
                heart_rate = sum(heart_rates) / len(heart_rates)

        if heart_rate:
            profile = StudentProfile.objects.get(user=request.user)
            status = 'Healthy'
            if heart_rate > 100 or heart_rate < 60:
                status = 'Unhealthy'

            VitalsSubmission.objects.create(
                student_profile=profile,
                heart_rate=int(heart_rate),
                spo2=98,
                temperature=98.6,
                health_status=status
            )
            messages.success(request, "Vitals synced from Google Fit successfully!")
        else:
            messages.warning(request, "No heart rate data found for the last 24 hours.")

    except GoogleFitToken.DoesNotExist:
        messages.error(request, "Please connect your Google Fit account first.")
    except requests.exceptions.RequestException as e:
        messages.error(request, f"API request failed: {e}")
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {e}")

    return redirect('dashboard')