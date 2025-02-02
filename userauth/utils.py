import secrets
import logging
from django.conf import settings
from django.core.mail import EmailMessage
from .models import User,OneTimePassword

logger = logging.getLogger(__name__)

def generate_otp():
    """
    Generat a random numeric OTP
    """
    return ''.join(secrets.choice('0123456789') for _ in range(6))
    

def create_otp_for_user(user):

    OneTimePassword.objects.filter(user=user).delete()

    otp = generate_otp()

    OneTimePassword.objects.create(user=user, otp=otp)

    return otp



def send_code_to_user(email, is_resend = False):
    
    try:
        user = User.objects.get(email__iexact=email)
        otp_code = create_otp_for_user(user)

        current_site=settings.SITE_NAME

        Subject = "New Verifciation Code" if is_resend else "Verify your Email"

        email_body = (
            f"Hi {user.username},\n\n"
            f"Your {'new' if is_resend else 'verification'} code for {current_site} is: {otp_code}\n"
            f"This code will expire in {settings.OTP_EXPIRY_MINUTES} minutes.\n\n"
            "If you didn't request this code, please ignore this email."
        )

        email = EmailMessage(
            subject=Subject,
            body=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email]
        )
        email.send(fail_silently=False)
        logger.info(f"OTP {'resent' if is_resend else 'sent'} to {email}")
        return True

    except User.DoesNotExist:
        logger.warning(f"Attempt to send OTP to non-existent email: {email}")
        return False
    except Exception as e:
        logger.error(f"Failed to send OTP to {email}: {str(e)}")
        OneTimePassword.objects.filter(user=user).delete()
        return False




def send_normal_email(data):

    email = EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[data['to_email']]
    )

    email.send()
