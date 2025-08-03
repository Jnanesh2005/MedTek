from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import StudentProfile, VitalsSubmission, GoogleFitToken

admin.site.register(StudentProfile)
admin.site.register(VitalsSubmission)
admin.site.register(GoogleFitToken)