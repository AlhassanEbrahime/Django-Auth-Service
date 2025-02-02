from django.urls import path
from .views import( 
    RegisterUserView, 
    VerifyUserEmail, 
    ResendOTPView, LoginUserView,
    PasswordResetConfirm,
    PasswordResetRequestView,
    SetNewPasswordView,
    TestView
)

from rest_framework_simplejwt.views import (TokenRefreshView,)



urlpatterns=[ 

    path('register/', RegisterUserView.as_view(), name = 'register'),
    path('verify-email/', VerifyUserEmail.as_view(),name='verify-email'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('login/',LoginUserView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset/',PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirm.as_view(),name='reset-password-confirm'),
    path('set-new-password/',SetNewPasswordView.as_view(),name='set-new-password'),
    path('test/',TestView.as_view())


]