import random
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.mail import send_mail
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

User = get_user_model()

class SenOtpSerializers(serializers.Serializer):
    email = serializers.EmailField()

    def save(self, **kwargs):
        email = self.validated_data['email']
        
        # Get or create the user so the email is saved in the User DB
        user, created = User.objects.get_or_create(email=email, defaults={'username': email})
        
        # Generate a 6-digit OTP
        otp = random.randint(100000, 999999)
        
        # Save OTP ONLY into the cache (valid for 5 minutes)
        cache.set(f'user_email:{email}', otp, timeout=300)
        
        # Send the email
        send_mail(
            subject='Salom',
            message=f'Sizning OTP codingiz: {otp}',
            from_email='ismatismoilov709@gmail.com',
            recipient_list=[email],
            fail_silently=False,
            )
        return user


class VerifySerializers(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        entered_otp = attrs.get('otp')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise ValidationError('No user found with this email address.')
            
        # Retrieve the OTP from the cache
        cached_otp = cache.get(f'user_email:{email}')
        
        # Check if OTP exists and matches
        if not cached_otp or str(cached_otp) != str(entered_otp):
            raise ValidationError('Invalid or expired OTP code.')
            
        attrs['user'] = user
        return attrs

    def save(self, **kwargs):
        # Clear the cache after successful verification
        email = self.validated_data['email']
        cache.delete(f'user_email:{email}')
        
        return self.validated_data['user']
