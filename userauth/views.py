import logging
from rest_framework.throttling import AnonRateThrottle
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .serializers import (

    UserRegisterSerializer, 
    LoginSerializer,
    PasswordResetRequestSerializer,
    SetNewPasswordSerializer
)

from .models import OneTimePassword,User
from .utils import send_code_to_user


logger = logging.getLogger(__name__)

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    
    @transaction.atomic
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = serializer.save() 
            logger.info(f"User {user.email} registered successfully")
        except Exception as e:
            logger.error(f"Registration failed: {str(e)}")
            return Response(
                {'message': 'Registration failed due to an error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        send_code_to_user(user.email)

        return Response(
            {'message': f"Hi {user.username}, verification code has been sent"},
            status=status.HTTP_201_CREATED
        )
   
    

class VerifyUserEmail(GenericAPIView):
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        otpcode = request.data.get('otp')

        # Check if otp is provided

        if not otpcode:
            logger.warning("Email verification attemp without otp")
            return Response(
                {'message':'OTP not provieded'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get and validate OTP
            user_otp_obj = OneTimePassword.objects.get(otp = otpcode)
            user = user_otp_obj.user

            # Check OTP expiry
            if user_otp_obj.is_expired():
                user_otp_obj.delete() # deleting expired otp
                logger.warning(f"Expired OTP attemp for user {user.email}")
                return Response(
                    {'message':"OTP has expired"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check the verification status
            if not user.is_verified:
                user.is_verified=True
                user.save()
                logger.info(f"Email verified successfully for user {user.email}")

                return Response(
                    { 'message':'email has been verified'},
                    status=status.HTTP_200_OK
                    ) 
            
            logger.warning(f"already verified user attemped verification: {user.email}")
            return Response(
                {'message':'User is already verified'}, 
                status=status.HTTP_208_ALREADY_REPORTED
                )
            
        except OneTimePassword.DoesNotExist:
            logger.warning(f"Invalid OTP attemp: {otpcode}")
            return Response({
                'message':'Invalid OTP'
            }, status= status.HTTP_404_NOT_FOUND)
        

    
        except Exception as e:
            logger.error(f"Unexpected error during email verification: {str(e)}")
            return Response(
                {'message': 'An error occurred during verification'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResendOTPView(GenericAPIView):
    throttle_classes = [AnonRateThrottle]

    def post(self,request):
        email = request.data.get('email')

        if not email:
            return Response(
                {'message':'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email__iexact = email)

            if user.is_verified:
                return Response(
                    {'message':'User is already verified'},
                    status = status.HTTP_409_CONFLICT
                )
            
            # Invalidate existing OTPs
            OneTimePassword.objects.filter(user=user).delete()

            # Generate and send new OTP
            if send_code_to_user(user.email, is_resend=True):
                return Response(
                    {'message':'New OTP sent Successfully'},
                    status=status.HTTP_200_OK
                )
            
            return Response(
                {'message':'Faild to send OTP'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        except User.DoesNotExist:
            logger.warning(f"Resend attemp for non existing email : {email}")
            return Response(
                {'message':'If this email exists, a new OTP was sent'},
                status=status.HTTP_200_OK
                )
        except Exception as e:
            logger.error(f"Resend OTP error: {str(e)}")
            return Response(
                {'message':'Faild to process request'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
     

class LoginUserView(GenericAPIView):
    throttle_classes =[AnonRateThrottle]
    serializer_class = LoginSerializer
    def post(self,request):
        serializer = self.serializer_class(data = request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    def post(self, request):
        serializer=self.serializer_class(data=request.data, context = {'request':request})
        serializer.is_valid(raise_exception = True)

        return Response(
            {'message':"Link has been sent t your email to reset your bassword"},
            status=status.HTTP_200_OK
        )
    

    

class PasswordResetConfirm(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {'message':'token is invalid or has expired'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            return Response(
                {
                    'success':True,
                    'message':'valid credentials',
                    'uidb64':uidb64,
                    'token':token
                },
                status=status.HTTP_200_OK
            )
        
        except DjangoUnicodeDecodeError:
            return Response(
                  {'message':'token is invalid or has expired'},
                    status=status.HTTP_401_UNAUTHORIZED
            )


class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    def patch(self,request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {'message':"password reset successfully"},
            status=status.HTTP_200_OK
        )
    


class TestView(GenericAPIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        return Response("it wroks", status=status.HTTP_200_OK)