from django.urls import path
from .views import GoogleOauthSignInView


urlpatterns=[
    path('google', GoogleOauthSignInView.as_view(), name='google'),
]