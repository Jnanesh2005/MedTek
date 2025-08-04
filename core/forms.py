from django import forms
from .models import StudentProfile, VitalsSubmission, User
from django.contrib.auth.forms import AuthenticationForm

class UserRegistrationForm(forms.Form):
    email = forms.EmailField(label="Email", required=True)

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(label="OTP", max_length=6, required=True)

class ProfileSetupForm(forms.ModelForm):
    pre_existing_diseases = forms.CharField(
        widget=forms.CheckboxSelectMultiple(choices=[
            ('Asthma', 'Asthma'),
            ('Diabetes', 'Diabetes'),
            ('Heart Disease', 'Heart Disease'),
            ('Hypertension', 'Hypertension'),
        ]),
        required=False
    )
    class Meta:
        model = StudentProfile
        exclude = ('user', 'email')
        widgets = {
            'pre_existing_diseases': forms.CheckboxSelectMultiple
        }

class VitalsSubmissionForm(forms.ModelForm):
    class Meta:
        model = VitalsSubmission
        fields = ['heart_rate', 'spo2', 'temperature', 'respiration_rate']
        # In core/forms.py, at the bottom
# In core/forms.py
class AdminRegistrationForm(forms.ModelForm):
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
    verification_code = forms.CharField(max_length=20, label="Verification Code", required=True)

    class Meta:
        model = User
        fields = ['username', 'email']

class AdminLoginForm(AuthenticationForm):
    pass
