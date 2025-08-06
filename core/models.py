from django.db import models
from django.contrib.auth.models import AbstractUser

# Define the custom User model first
class User(AbstractUser):
    is_school_staff = models.BooleanField(default=False)

# Now, define the other models that reference the custom User model
class StudentProfile(models.Model):
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    age = models.IntegerField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    school_name = models.CharField(max_length=200)
    height = models.FloatField(help_text="in cm")
    weight = models.FloatField(help_text="in kg")
    pre_existing_diseases = models.TextField(blank=True, help_text="Separate with commas")
    contact_number = models.CharField(max_length=20)
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.name

class VitalsSubmission(models.Model):
    student_profile = models.ForeignKey(StudentProfile, on_delete=models.CASCADE)
    heart_rate = models.IntegerField(help_text="in bpm")
    spo2 = models.IntegerField(help_text="in %")
    temperature = models.FloatField(help_text="in °F")
    respiration_rate = models.IntegerField(null=True, blank=True, help_text="in breaths per minute")
    submission_date = models.DateTimeField(auto_now_add=True)
    health_status = models.CharField(max_length=20, default='Healthy')

    def __str__(self):
        return f"Vitals for {self.student_profile.name} on {self.submission_date.strftime('%Y-%m-%d')}"

class OTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

class GoogleFitToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    access_token = models.CharField(max_length=255)
    refresh_token = models.CharField(max_length=255, null=True, blank=True)
    token_uri = models.CharField(max_length=255, null=True, blank=True)
    client_id = models.CharField(max_length=255)
    client_secret = models.CharField(max_length=255)
    scopes = models.TextField(null=True, blank=True)    expires_in = models.DateTimeField()

    def __str__(self):
        return f"Token for {self.user.username}"
    
class AdminVerificationCode(models.Model):
    code = models.CharField(max_length=20, unique=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return self.code