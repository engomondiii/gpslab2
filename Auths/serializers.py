from rest_framework import serializers
from .models import CustomUser
from django.core.mail import send_mail
from google.auth.transport import requests
from google.oauth2 import id_token
import logging
import requests as http_requests
import jwt

# Set up a logger
logger = logging.getLogger(__name__)

class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for registering a new user.
    """
    first_name = serializers.CharField(required=True, error_messages={"blank": "First name is required."})
    last_name = serializers.CharField(required=True, error_messages={"blank": "Last name is required."})
    email = serializers.EmailField(required=True, error_messages={"blank": "Email is required."})

    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'password', 'first_name', 'last_name')
        extra_kwargs = {
            'password': {'write_only': True, 'error_messages': {"blank": "Password is required."}},
            'username': {'required': True, 'error_messages': {"blank": "Username is required."}},
        }

    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty or whitespace.")
        return value

    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty or whitespace.")
        return value

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        try:
            # Create user and generate OTP
            user = CustomUser.objects.create_user(**validated_data)
            user.auth_provider = 'email'  # Set authentication provider
            user.generate_otp()  # Generate OTP for email verification

            # Log successful user creation
            logger.info(f"User {user.email} registered successfully with OTP {user.otp}.")

            # Send OTP to user's email
            send_mail(
                'Your OTP for GPS Platform',
                f'Your OTP is: {user.otp}',
                'GPS Platform <gpslab@iwl.kr>',
                [user.email],
                fail_silently=False,
            )
            return user
        except Exception as e:
            logger.error(f"Error during user creation: {e}")
            raise serializers.ValidationError("An error occurred during registration. Please try again.")

class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer for Google OAuth authentication.
    """
    id_token = serializers.CharField(required=True)
    
    def validate_id_token(self, value):
        """
        Validate Google ID token and extract user information.
        """
        try:
            # Verify the token with Google
            # You'll need to add your Google OAuth client ID to settings
            from django.conf import settings
            
            idinfo = id_token.verify_oauth2_token(
                value, 
                requests.Request(), 
                settings.GOOGLE_OAUTH2_CLIENT_ID
            )
            
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise serializers.ValidationError('Invalid token issuer.')
            
            return {
                'google_id': idinfo['sub'],
                'email': idinfo['email'],
                'first_name': idinfo.get('given_name', ''),
                'last_name': idinfo.get('family_name', ''),
                'profile_picture_url': idinfo.get('picture', ''),
                'email_verified': idinfo.get('email_verified', False)
            }
            
        except ValueError as e:
            logger.error(f"Invalid Google token: {e}")
            raise serializers.ValidationError("Invalid Google token.")
        except Exception as e:
            logger.error(f"Google token validation error: {e}")
            raise serializers.ValidationError("Failed to validate Google token.")

    def validate(self, data):
        """
        Process Google authentication.
        """
        google_data = self.validate_id_token(data['id_token'])
        
        # Check if user already exists with this Google ID
        user = CustomUser.get_by_social_id('google', google_data['google_id'])
        
        if user:
            # User exists, return existing user
            return {'user': user, 'created': False}
        
        # Check if user exists with this email (link accounts)
        try:
            existing_user = CustomUser.objects.get(email=google_data['email'])
            if existing_user.auth_provider == 'email':
                # Link Google account to existing email account
                user = CustomUser.link_social_account(
                    existing_user,
                    'google',
                    google_data['google_id'],
                    google_data['profile_picture_url']
                )
                logger.info(f"Linked Google account to existing user: {user.email}")
                return {'user': user, 'created': False, 'linked': True}
            else:
                raise serializers.ValidationError("An account with this email already exists with a different provider.")
        except CustomUser.DoesNotExist:
            pass
        
        # Create new user with Google authentication
        try:
            user = CustomUser.create_social_user(
                provider='google',
                social_id=google_data['google_id'],
                email=google_data['email'],
                first_name=google_data['first_name'],
                last_name=google_data['last_name'],
                profile_picture_url=google_data['profile_picture_url']
            )
            logger.info(f"Created new Google user: {user.email}")
            return {'user': user, 'created': True}
            
        except Exception as e:
            logger.error(f"Error creating Google user: {e}")
            raise serializers.ValidationError("Failed to create user account.")

class AppleAuthSerializer(serializers.Serializer):
    """
    Serializer for Apple OAuth authentication.
    """
    id_token = serializers.CharField(required=True)
    
    def validate_id_token(self, value):
        """
        Validate Apple ID token and extract user information.
        """
        try:
            from django.conf import settings
            
            # Decode the JWT token without verification first to get the header
            unverified_header = jwt.get_unverified_header(value)
            
            # Get Apple's public keys
            apple_keys_url = "https://appleid.apple.com/auth/keys"
            response = http_requests.get(apple_keys_url)
            apple_keys = response.json()
            
            # Find the correct key
            key = None
            for apple_key in apple_keys['keys']:
                if apple_key['kid'] == unverified_header['kid']:
                    key = apple_key
                    break
            
            if not key:
                raise serializers.ValidationError("Unable to find matching key.")
            
            # Convert the key to PEM format
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import base64
            
            n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '==='), 'big')
            e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '==='), 'big')
            
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            pem_key = public_key.serialize(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Verify and decode the token
            decoded_token = jwt.decode(
                value,
                pem_key,
                algorithms=['RS256'],
                audience=settings.APPLE_OAUTH2_CLIENT_ID,
                issuer='https://appleid.apple.com'
            )
            
            return {
                'apple_id': decoded_token['sub'],
                'email': decoded_token.get('email', ''),
                'first_name': decoded_token.get('given_name', ''),
                'last_name': decoded_token.get('family_name', ''),
                'email_verified': decoded_token.get('email_verified', False)
            }
            
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid Apple token: {e}")
            raise serializers.ValidationError("Invalid Apple token.")
        except Exception as e:
            logger.error(f"Apple token validation error: {e}")
            raise serializers.ValidationError("Failed to validate Apple token.")

    def validate(self, data):
        """
        Process Apple authentication.
        """
        apple_data = self.validate_id_token(data['id_token'])
        
        # Check if user already exists with this Apple ID
        user = CustomUser.get_by_social_id('apple', apple_data['apple_id'])
        
        if user:
            # User exists, return existing user
            return {'user': user, 'created': False}
        
        # Check if user exists with this email (link accounts)
        if apple_data['email']:
            try:
                existing_user = CustomUser.objects.get(email=apple_data['email'])
                if existing_user.auth_provider == 'email':
                    # Link Apple account to existing email account
                    user = CustomUser.link_social_account(
                        existing_user,
                        'apple',
                        apple_data['apple_id']
                    )
                    logger.info(f"Linked Apple account to existing user: {user.email}")
                    return {'user': user, 'created': False, 'linked': True}
                else:
                    raise serializers.ValidationError("An account with this email already exists with a different provider.")
            except CustomUser.DoesNotExist:
                pass
        
        # Create new user with Apple authentication
        try:
            # Generate email if not provided by Apple
            email = apple_data['email'] or f"apple_{apple_data['apple_id']}@privaterelay.appleid.com"
            
            user = CustomUser.create_social_user(
                provider='apple',
                social_id=apple_data['apple_id'],
                email=email,
                first_name=apple_data['first_name'],
                last_name=apple_data['last_name']
            )
            logger.info(f"Created new Apple user: {user.email}")
            return {'user': user, 'created': True}
            
        except Exception as e:
            logger.error(f"Error creating Apple user: {e}")
            raise serializers.ValidationError("Failed to create user account.")

class SocialAuthResponseSerializer(serializers.Serializer):
    """
    Serializer for social authentication responses.
    """
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    user = serializers.SerializerMethodField()
    created = serializers.BooleanField(read_only=True)
    linked = serializers.BooleanField(read_only=True, default=False)
    
    def get_user(self, obj):
        return UserProfileSerializer(obj['user']).data

class VerifyOtpSerializer(serializers.Serializer):
    """
    Serializer for verifying the OTP sent to the user's email.
    """
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            
            # Only allow OTP verification for email-based accounts
            if user.auth_provider != 'email':
                raise serializers.ValidationError("OTP verification is not available for social accounts.")
            
            if user.is_otp_expired():
                raise serializers.ValidationError("OTP has expired.")
            if user.otp != data['otp']:
                raise serializers.ValidationError("Invalid OTP.")
            user.is_verified = True
            user.clear_otp()
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

class LoginSerializer(serializers.Serializer):
    """
    Serializer for logging in a user.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            
            # Only allow password login for email-based accounts
            if user.auth_provider != 'email':
                raise serializers.ValidationError("Password login is not available for social accounts. Please use social login.")
            
            if not user.check_password(data['password']):
                raise serializers.ValidationError("Invalid email or password.")
            if not user.is_verified:
                raise serializers.ValidationError("Email not verified. Please verify your account.")
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving and updating user profile details.
    """
    profile_picture_url = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = (
            'first_name',
            'last_name',
            'email',
            'username',
            'profile_picture',
            'profile_picture_url',
            'is_verified',
            'registration_date',
            'auth_provider',
            'is_social_account',
            'has_social_account'
        )
        read_only_fields = (
            'is_verified', 
            'registration_date', 
            'profile_picture',
            'auth_provider',
            'is_social_account'
        )
    
    def get_profile_picture_url(self, obj):
        return obj.get_profile_picture_url()
    
    def get_has_social_account(self, obj):
        return obj.has_social_account()

class UpdateProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user details (excluding password and profile picture).
    """
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'username')

    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty.")
        return value

    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty.")
        return value

    def validate_email(self, value):
        user = self.instance
        # Prevent email updates for social accounts
        if user.auth_provider != 'email':
            raise serializers.ValidationError("Email cannot be updated for social accounts.")
        return value

    def update(self, instance, validated_data):
        instance.update_profile(
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            email=validated_data.get('email'),
            username=validated_data.get('username'),
        )
        return instance

class UpdateProfilePictureSerializer(serializers.ModelSerializer):
    """
    Serializer for updating the user's profile picture.
    """
    profile_picture = serializers.ImageField()

    class Meta:
        model = CustomUser
        fields = ('profile_picture',)

    def update(self, instance, validated_data):
        instance.update_profile_picture(validated_data.get('profile_picture'))
        return instance

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing the user's password.
    """
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        
        # Only allow password changes for email-based accounts
        if user.auth_provider != 'email':
            raise serializers.ValidationError("Password change is not available for social accounts.")
        
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError("Old password is incorrect.")
        if data['old_password'] == data['new_password']:
            raise serializers.ValidationError("New password cannot be the same as the old password.")
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class TokenSerializer(serializers.Serializer):
    """
    Serializer for generating JWT tokens.
    """
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

class ForgotPasswordSerializer(serializers.Serializer):
    """
    Serializer for initiating forgot password flow by sending OTP.
    """
    email = serializers.EmailField()

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            
            # Only allow password reset for email-based accounts
            if not user.can_reset_password():
                raise serializers.ValidationError("Password reset is not available for social accounts.")
            
            user.generate_reset_password_otp()

            # Send OTP to user's email
            send_mail(
                'Reset Your Password - GPS Platform',
                f'Your OTP is: {user.reset_password_otp}',
                'GPS Platform <gpslab@iwl.kr>',
                [user.email],
                fail_silently=False,
            )
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

class VerifyResetOtpSerializer(serializers.Serializer):
    """
    Serializer for verifying the OTP sent for password reset.
    """
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            
            # Only allow for email-based accounts
            if user.auth_provider != 'email':
                raise serializers.ValidationError("Password reset is not available for social accounts.")
            
            if user.is_reset_password_otp_expired():
                raise serializers.ValidationError("OTP has expired.")
            if user.reset_password_otp != data['otp']:
                raise serializers.ValidationError("Invalid OTP.")
            user.clear_reset_password_otp()
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for resetting the user's password.
    """
    email = serializers.EmailField()
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            
            # Only allow for email-based accounts
            if user.auth_provider != 'email':
                raise serializers.ValidationError("Password reset is not available for social accounts.")
            
            user.set_password(data['new_password'])
            user.save()
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")

class AccountLinkingSerializer(serializers.Serializer):
    """
    Serializer for linking social accounts to existing email accounts.
    """
    provider = serializers.ChoiceField(choices=['google', 'apple'])
    id_token = serializers.CharField(required=True)
    
    def validate(self, data):
        user = self.context['request'].user
        
        if user.auth_provider != 'email':
            raise serializers.ValidationError("Account linking is only available for email-based accounts.")
        
        provider = data['provider']
        id_token = data['id_token']
        
        # Validate token based on provider
        if provider == 'google':
            google_serializer = GoogleAuthSerializer(data={'id_token': id_token})
            if google_serializer.is_valid():
                social_data = google_serializer.validate_id_token(id_token)
                social_id = social_data['google_id']
                profile_picture_url = social_data['profile_picture_url']
            else:
                raise serializers.ValidationError(google_serializer.errors)
        elif provider == 'apple':
            apple_serializer = AppleAuthSerializer(data={'id_token': id_token})
            if apple_serializer.is_valid():
                social_data = apple_serializer.validate_id_token(id_token)
                social_id = social_data['apple_id']
                profile_picture_url = None
            else:
                raise serializers.ValidationError(apple_serializer.errors)
        
        # Check if social account is already linked to another user
        existing_user = CustomUser.get_by_social_id(provider, social_id)
        if existing_user and existing_user != user:
            raise serializers.ValidationError(f"This {provider} account is already linked to another user.")
        
        # Link the account
        linked_user = CustomUser.link_social_account(
            user, provider, social_id, profile_picture_url
        )
        
        return {'user': linked_user, 'provider': provider}