from django.core.management.base import BaseCommand
from core.models import GoogleFitToken, VitalsSubmission, StudentProfile
import requests
import datetime
import json
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Syncs health data from Google Fit for all users.'

    def handle(self, *args, **kwargs):
        self.stdout.write(self.style.SUCCESS("Starting Google Fit data sync..."))
        
        # Get the time for the last 24 hours
        now = datetime.datetime.now(datetime.timezone.utc)
        end_time_millis = int(now.timestamp() * 1000)
        start_time_millis = int((now - datetime.timedelta(days=1)).timestamp() * 1000)

        for token_obj in GoogleFitToken.objects.all():
            try:
                # Refresh the token if it's expired
                # (This is a simplified check, a full implementation would use a refresh flow)
                # For now, we'll assume the token is valid for prototyping.

                # Fetch heart rate data
                headers = {'Authorization': f'Bearer {token_obj.access_token}'}
                
                # Google Fit Aggregation API endpoint
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
                response.raise_for_status()  # Raise an error for bad status codes
                
                data = response.json()
                
                # Check for and extract heart rate data
                heart_rate = None
                if data.get('bucket') and data['bucket'][0].get('dataset') and data['bucket'][0]['dataset'][0].get('point'):
                    points = data['bucket'][0]['dataset'][0]['point']
                    if points:
                        # Calculate the average heart rate for the day
                        heart_rates = [p['value'][0]['fpVal'] for p in points]
                        heart_rate = sum(heart_rates) / len(heart_rates)

                if heart_rate:
                    profile = StudentProfile.objects.get(user=token_obj.user)
                    
                    # Use your existing health prediction logic
                    status = 'Healthy'
                    if heart_rate > 100 or heart_rate < 60: # Example logic
                         status = 'Unhealthy'

                    # Create a new VitalsSubmission entry
                    VitalsSubmission.objects.create(
                        student_profile=profile,
                        heart_rate=int(heart_rate),
                        spo2=98,  # Placeholder, a real app would fetch this
                        temperature=98.6, # Placeholder
                        health_status=status
                    )
                    self.stdout.write(self.style.SUCCESS(f'Successfully synced heart rate for {token_obj.user.username}'))

            except StudentProfile.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"No profile found for user {token_obj.user.username}"))
            except requests.exceptions.RequestException as e:
                self.stdout.write(self.style.ERROR(f"API request failed for {token_obj.user.username}: {e}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"An unexpected error occurred for {token_obj.user.username}: {e}"))
        
        self.stdout.write(self.style.SUCCESS("Google Fit data sync complete."))