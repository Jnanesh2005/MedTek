from django.contrib import admin
from .models import StudentProfile, VitalsSubmission, GoogleFitToken, AdminVerificationCode, User

admin.site.register(StudentProfile)
admin.site.register(VitalsSubmission)
admin.site.register(GoogleFitToken)
admin.site.register(AdminVerificationCode)
admin.site.register(User)