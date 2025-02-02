from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
from .utils import register_social_user,GoogleAuth



class GoogleSignInSerializer(serializers.Serializer):
    access_token=serializers.CharField(min_length=6)


    def validate_access_token(self, access_token):
        user_data=GoogleAuth.validate(access_token)
        try:
            user_data['sub']
            
        except:
            raise serializers.ValidationError("this token has expired or invalid please try again")
        
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
                raise AuthenticationFailed('Could not verify user.')

        user_id=user_data['sub']
        email=user_data['email']
        username = user_data['name']
        provider='google'

        return register_social_user(provider, email, username)
