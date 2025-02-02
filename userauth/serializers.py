from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import smart_str,smart_bytes,force_str
from django.urls import reverse
from .utils import send_normal_email
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password



class UserRegisterSerializer(serializers.ModelSerializer):
      
      password = serializers.CharField(max_length=68, min_length=8, write_only = True)
      password_confirmation =  serializers.CharField(max_length=68, min_length=8, write_only = True)


      class Meta:
            model = User
            fields = ['username', 'email', 'password', 'password_confirmation']


      def validate(self, attrs):
            password = attrs.get('password', '')
            password_confirmation = attrs.get('password_confirmation', '')

            if password != password_confirmation:
                  raise serializers.ValidationError("passwords do not match")
            
            return attrs



      def create(self, validated_data):
            validated_data.pop('password_confirmation') 
            user = User.objects.create_user(
                  email = validated_data['email'],
                  username = validated_data['username'],
                  password = validated_data['password'],
            )

            return user       
      


class LoginSerializer(serializers.ModelSerializer):
      email = serializers.EmailField(max_length=255)
      password = serializers.CharField(max_length=68, write_only = True)
      username = serializers.CharField(max_length=255, read_only = True)
      access_token = serializers.CharField(max_length=255, read_only = True)
      refresh_token = serializers.CharField(max_length=255, read_only = True)


      class Meta:
            model=User
            fields=['email', 'password', 'username', 'access_token', 'refresh_token']


      def validate(self, attrs):
            email = attrs.get('email')
            password = attrs.get('password')
            request = self.context.get('request')
            user = authenticate(request, email=email, password=password)

            if not user:
               raise AuthenticationFailed("Invalid credentials try again")
            
            
            user_tokens = user.tokens()

            return {

                  'email':user.email,
                  'username':user.username,
                  'access_token':str(user_tokens.get('access')),
                  'refresh_token':str(user_tokens.get('refresh'))
            }

      

class PasswordResetRequestSerializer(serializers.Serializer):
      email =serializers.EmailField(max_length=255)


      def validate(self, attrs):
           email = attrs.get('email')
           user = User.objects.filter(email=email).first()

           if not user:
             raise serializers.ValidationError(
                  {'message':"User with this email does not exist."},
                  code = 'anon user'
            )
           
           self._send_password_reset_email(user)

           return attrs   



      def _send_password_reset_email(self, user):

           """
           Helper method to generate and send password resent email
           """  

           uidb64=urlsafe_base64_encode(smart_bytes(user.id))
           token = PasswordResetTokenGenerator().make_token(user)

           request = self.context.get('request')
           site_domain = get_current_site(request).domain
           protocol = 'https' if request.is_secure() else 'http'


           relative_link = reverse(
            'reset-password-confirm',
            kwargs={'uidb64': uidb64, 'token': token}
           )

           abslink = f"{protocol}://{site_domain}{relative_link}"
           print(abslink)
           email_body = f"hi use this link to reset your password \n {abslink}"


           send_normal_email({
            'email_body': email_body,
            'email_subject': 'Password Reset Instructions',
            'to_email': user.email
          })



             


class SetNewPasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64=serializers.CharField(min_length=1, write_only=True)
    token=serializers.CharField(min_length=3, write_only=True)



    def validate(self, attrs):
         password = attrs.get('password')
         confirm_password = attrs.get('confirm_password')
         uidb64 = attrs.get('uidb64')
         token = attrs.get('token')

         self._validate_password_match(password, confirm_password)
         user = self._validate_token_and_uid(uidb64, token)
         self._update_user_password(user, password)

         return attrs
      

    def _validate_password_match(self, password, confirm_passowrd):
         
         """
         Ensure that password and confirmation match
         """
         if password != confirm_passowrd:
              raise serializers.ValidationError(
                   {"password":"Passwords don't match"},
                   code="password_mismatch"
              )
         

    def _validate_token_and_uid(self, uidb64, token):

         """
         Validate the uid and resest password token
         """      
         try:
              user_id = force_str(urlsafe_base64_decode(uidb64))
              user = User.objects.get(id=user_id)

              if not PasswordResetTokenGenerator().check_token(user,token):
                  raise AuthenticationFailed(
                    "Reset link is invalid or has expired",
                    code ='Invalid_token'
                  )
              
              return user
         
         except(UnicodeDecodeError, ValueError, OverflowError, User.DoesNotExist):
              raise AuthenticationFailed(
                   "Invalid reset Link",
                   code = "Invalid_uid"
              )
      

    def _update_user_password(self, user, password):
         
         """
         update and save user password
         """
         user.set_password(password)
         user.save()
