from rest_framework import serializers
from .models import CustomUser
from django.core.mail import send_mail
import logging

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
            user.generate_otp()  # Generate OTP for email verification

            # Log successful user creation
            logger.info(f"User {user.email} registered successfully with OTP {user.otp}.")

            # Send OTP to user's email
            send_mail(
                'Your OTP for Lab4GPS',
                f'Your OTP is: {user.otp}',
                'Lab4GPS <lab4gps@gmail.com>',
                [user.email],
                fail_silently=False,
            )
            return user
        except Exception as e:
            logger.error(f"Error during user creation: {e}")
            raise serializers.ValidationError("An error occurred during registration. Please try again.")

class VerifyOtpSerializer(serializers.Serializer):
    """
    Serializer for verifying the OTP sent to the user's email.
    """
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
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
    class Meta:
        model = CustomUser
        fields = (
            'first_name',
            'last_name',
            'email',
            'username',
            'profile_picture',
            'is_verified',
            'registration_date'
        )
        read_only_fields = ('is_verified', 'registration_date', 'profile_picture')

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
            user.generate_reset_password_otp()

            # Send OTP to user's email
            send_mail(
                'Reset Your Password - Lab4GPS',
                f'Your OTP is: {user.reset_password_otp}',
                'Lab4GPS <lab4gps@gmail.com>',
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
            user.set_password(data['new_password'])
            user.save()
            return user
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")
