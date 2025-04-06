from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
import random

class CustomUser(AbstractUser):
    """
    Custom user model extending AbstractUser.
    Adds fields for email verification, OTP functionality, and profile management.
    """
    email = models.EmailField(
        unique=True, 
        verbose_name="Email Address", 
        error_messages={
            "unique": "A user with this email already exists."
        }
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name="Is Verified",
        help_text="Indicates whether the email is verified."
    )
    otp = models.CharField(
        max_length=6,
        blank=True,
        null=True,
        verbose_name="One-Time Password (OTP)"
    )
    otp_created_at = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="OTP Created At"
    )
    reset_password_otp = models.CharField(
        max_length=6,
        blank=True,
        null=True,
        verbose_name="Password Reset OTP"
    )
    reset_password_otp_created_at = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name="Password Reset OTP Created At"
    )
    profile_picture = models.ImageField(
        upload_to="profile_pictures/",
        blank=True,
        null=True,
        default="profile_pictures/default.jpg",
        verbose_name="Profile Picture"
    )
    registration_date = models.DateTimeField(
        default=timezone.now,
        verbose_name="Registration Date"
    )

    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    def __str__(self):
        return f"{self.username} ({self.email})"

    # OTP Methods
    def generate_otp(self):
        """
        Generate a random 6-digit OTP for email verification.
        """
        self.otp = str(random.randint(100000, 999999))
        self.otp_created_at = timezone.now()
        self.save()

    def clear_otp(self):
        """
        Clear the email verification OTP after verification.
        """
        self.otp = None
        self.otp_created_at = None
        self.save()

    def is_otp_expired(self):
        """
        Check if the email verification OTP is expired.
        """
        if self.otp_created_at:
            expiry_time = self.otp_created_at + timedelta(minutes=10)
            return timezone.now() > expiry_time
        return True

    # Password Reset OTP Methods
    def generate_reset_password_otp(self):
        """
        Generate a random 6-digit OTP for password reset.
        """
        self.reset_password_otp = str(random.randint(100000, 999999))
        self.reset_password_otp_created_at = timezone.now()
        self.save()

    def clear_reset_password_otp(self):
        """
        Clear the password reset OTP after successful reset.
        """
        self.reset_password_otp = None
        self.reset_password_otp_created_at = None
        self.save()

    def is_reset_password_otp_expired(self):
        """
        Check if the password reset OTP is expired.
        """
        if self.reset_password_otp_created_at:
            expiry_time = self.reset_password_otp_created_at + timedelta(minutes=10)
            return timezone.now() > expiry_time
        return True

    # Profile Update Methods
    def update_profile(self, first_name=None, last_name=None, email=None, username=None):
        """
        Update user profile details.
        """
        if first_name:
            self.first_name = first_name
        if last_name:
            self.last_name = last_name
        if email:
            self.email = email
        if username:
            self.username = username
        self.save()

    def update_profile_picture(self, picture):
        """
        Update user profile picture.
        """
        self.profile_picture = picture
        self.save()

    def change_password(self, old_password, new_password):
        """
        Change the user's password after verifying the old password.
        """
        if self.check_password(old_password):
            self.set_password(new_password)
            self.save()
            return True
        return False
