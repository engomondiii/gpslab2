from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
import random

class CustomUser(AbstractUser):
    """
    Custom user model extending AbstractUser.
    Adds fields for email verification, OTP functionality, social authentication, and profile management.
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
    
    # Social Authentication Fields
    AUTH_PROVIDER_CHOICES = [
        ('email', 'Email'),
        ('google', 'Google'),
        ('apple', 'Apple'),
    ]
    
    auth_provider = models.CharField(
        max_length=20,
        choices=AUTH_PROVIDER_CHOICES,
        default='email',
        verbose_name="Authentication Provider",
        help_text="The provider used for user authentication"
    )
    social_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name="Social ID",
        help_text="Unique ID from social provider (Google ID, Apple ID, etc.)"
    )
    google_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        unique=True,
        verbose_name="Google ID",
        help_text="Google account unique identifier"
    )
    apple_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        unique=True,
        verbose_name="Apple ID",
        help_text="Apple account unique identifier"
    )
    social_profile_picture_url = models.URLField(
        blank=True,
        null=True,
        verbose_name="Social Profile Picture URL",
        help_text="Profile picture URL from social provider"
    )
    is_social_account = models.BooleanField(
        default=False,
        verbose_name="Is Social Account",
        help_text="Indicates if this account was created via social authentication"
    )

    REQUIRED_FIELDS = ["email", "first_name", "last_name"]

    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['google_id']),
            models.Index(fields=['apple_id']),
            models.Index(fields=['auth_provider']),
        ]

    def __str__(self):
        return f"{self.username} ({self.email}) - {self.get_auth_provider_display()}"

    def save(self, *args, **kwargs):
        # Auto-verify social accounts
        if self.is_social_account and not self.is_verified:
            self.is_verified = True
        
        # Set social_id based on provider
        if self.auth_provider == 'google' and self.google_id:
            self.social_id = self.google_id
        elif self.auth_provider == 'apple' and self.apple_id:
            self.social_id = self.apple_id
            
        super().save(*args, **kwargs)

    # OTP Methods
    def generate_otp(self):
        """
        Generate a random 6-digit OTP for email verification.
        Only generate OTP for email-based accounts.
        """
        if self.auth_provider == 'email':
            self.otp = str(random.randint(100000, 999999))
            self.otp_created_at = timezone.now()
            self.save()
        else:
            # Social accounts don't need OTP verification
            self.is_verified = True
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
        Only applicable for email-based accounts.
        """
        if self.auth_provider == 'email':
            self.reset_password_otp = str(random.randint(100000, 999999))
            self.reset_password_otp_created_at = timezone.now()
            self.save()
        else:
            raise ValueError("Password reset via OTP is not available for social accounts.")

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
        if email and self.auth_provider == 'email':
            # Only allow email updates for email-based accounts
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
        Only applicable for email-based accounts.
        """
        if self.auth_provider != 'email':
            raise ValueError("Password change is not available for social accounts.")
        
        if self.check_password(old_password):
            self.set_password(new_password)
            self.save()
            return True
        return False

    # Social Authentication Methods
    @classmethod
    def create_social_user(cls, provider, social_id, email, first_name=None, last_name=None, 
                          profile_picture_url=None, **extra_fields):
        """
        Create a new user account from social authentication.
        """
        # Generate unique username if not provided
        if 'username' not in extra_fields:
            base_username = email.split('@')[0]
            username = base_username
            counter = 1
            while cls.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            extra_fields['username'] = username

        # Create user
        user = cls.objects.create_user(
            username=extra_fields['username'],
            email=email,
            first_name=first_name or '',
            last_name=last_name or '',
            is_verified=True,  # Social accounts are pre-verified
            is_social_account=True,
            auth_provider=provider,
            social_profile_picture_url=profile_picture_url,
            **extra_fields
        )

        # Set provider-specific ID
        if provider == 'google':
            user.google_id = social_id
        elif provider == 'apple':
            user.apple_id = social_id
        
        user.social_id = social_id
        user.save()
        
        return user

    @classmethod
    def get_by_social_id(cls, provider, social_id):
        """
        Get user by social provider ID.
        """
        try:
            if provider == 'google':
                return cls.objects.get(google_id=social_id)
            elif provider == 'apple':
                return cls.objects.get(apple_id=social_id)
            else:
                return cls.objects.get(social_id=social_id, auth_provider=provider)
        except cls.DoesNotExist:
            return None

    @classmethod
    def link_social_account(cls, user, provider, social_id, profile_picture_url=None):
        """
        Link an existing email account to a social provider.
        """
        if provider == 'google':
            user.google_id = social_id
        elif provider == 'apple':
            user.apple_id = social_id
        
        user.social_id = social_id
        user.auth_provider = provider
        user.is_social_account = True
        user.is_verified = True
        
        if profile_picture_url:
            user.social_profile_picture_url = profile_picture_url
        
        user.save()
        return user

    def can_reset_password(self):
        """
        Check if user can reset password (only email-based accounts).
        """
        return self.auth_provider == 'email'

    def has_social_account(self):
        """
        Check if user has any linked social accounts.
        """
        return bool(self.google_id or self.apple_id)

    def get_profile_picture_url(self):
        """
        Get the profile picture URL, prioritizing uploaded image over social profile picture.
        """
        if self.profile_picture:
            return self.profile_picture.url
        elif self.social_profile_picture_url:
            return self.social_profile_picture_url
        return None