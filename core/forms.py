from django import forms
from .models import StudentProfile, VitalsSubmission, User

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