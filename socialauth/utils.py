from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
from userauth.models import User

from rest_framework.exceptions import ValidationError

class GoogleAuth:
    """
    Handles Google OAuth token validation.
    """

    @staticmethod
    def validate(access_token):
        try:
            id_info=id_token.verify_oauth2_token(access_token, requests.Request())
            if 'accounts.google.com' in id_info['iss']:
                return id_info
        except:
            return "the token is either invalid or has expired"

  
            
def register_social_user(provider, email, username):
    user = User.objects.filter(email=email).first()
    
    if user:
        if user.auth_provider == provider:
            authenticated_user = authenticate(email=email, password=settings.SOCIAL_AUTH_PASSWORD)
            
            if authenticated_user:
                return {
                    'email': authenticated_user.email,
                    'username': authenticated_user.username,
                    'tokens': authenticated_user.tokens()
                }
            raise AuthenticationFailed("Authentication failed.")
        
        raise AuthenticationFailed(f"Please continue your login with {user.auth_provider}.")
    
    new_user = User.objects.create_user(
        email=email,
        username=username,
        password=settings.SOCIAL_AUTH_PASSWORD
    )
    new_user.auth_provider = provider
    new_user.is_verified = True
    new_user.save()

    login_user = authenticate(email=email, password=settings.SOCIAL_AUTH_PASSWORD)
    if not login_user:
        raise AuthenticationFailed("Authentication failed after user creation.")

    tokens = login_user.tokens()
    return {
        'email': login_user.email,
        'username': login_user.username,
        "access_token": str(tokens.get('access')),
        "refresh_token": str(tokens.get('refresh'))
    }
