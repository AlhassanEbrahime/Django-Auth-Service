from django.db import transaction, IntegrityError
from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _
from django.utils.html import escape




class UserManager(BaseUserManager):

    def normalize_email(self,email):

        return super().normalize_email(email).lower()
    
    def email_validator(self,email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("please enter a valid email address"))


    def create_user(self,email, username, password, **extra_fields):

        if self.model.objects.filter(email=email).exists():
             raise ValueError(_("User registration failed. Please try again later."))

        email = self.normalize_email(email)
        self.email_validator(email)

        if not username:
            raise ValueError(_("Username is required"))
        
        try: 
            with transaction.atomic():
                user = self.model(
                    email = email,
                    username = username,
                    **extra_fields
                )
                
                user.set_password(password)
                user.save(using=self._db)
                return user

        except IntegrityError as e:

            if "email" in str(e):
                raise ValueError(_("Email already registered"))
            if "username" in str(e):
                raise ValueError(_("Username already taken"))   
            raise
        



    
    def create_superuser(self, email, username, password, **extra_fields):

        extra_fields.setdefault("is_staff",True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)


        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("is staff must be true for admin user"))
        
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("is staff must be true for admin user"))
        

        return self.create_user(email, username, password, **extra_fields)
       