from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import CustomUser
from .serializers import (
    RegisterSerializer,
    GoogleAuthSerializer,
    AppleAuthSerializer,
    SocialAuthResponseSerializer,
    VerifyOtpSerializer,
    LoginSerializer,
    UserProfileSerializer,
    UpdateProfileSerializer,
    UpdateProfilePictureSerializer,
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    VerifyResetOtpSerializer,
    ResetPasswordSerializer,
    AccountLinkingSerializer,
)
import logging

logger = logging.getLogger(__name__)

class RegisterView(generics.CreateAPIView):
    """
    API endpoint for user registration.
    """
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Validate request data for first_name and last_name
        if "first_name" not in request.data or "last_name" not in request.data:
            return Response(
                {"error": "First name and last name are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Registration successful. OTP sent to your email."},
            status=status.HTTP_201_CREATED,
        )

class GoogleAuthView(generics.GenericAPIView):
    """
    API endpoint for Google OAuth authentication.
    """
    serializer_class = GoogleAuthSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Authenticate user with Google ID token.
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            auth_data = serializer.validated_data
            user = auth_data['user']
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            response_data = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': user,
                'created': auth_data.get('created', False),
                'linked': auth_data.get('linked', False)
            }
            
            # Use the response serializer for consistent formatting
            response_serializer = SocialAuthResponseSerializer(response_data)
            
            logger.info(f"Google authentication successful for user: {user.email}")
            
            return Response(
                response_serializer.data,
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Google authentication failed: {str(e)}")
            return Response(
                {"error": "Google authentication failed. Please try again."},
                status=status.HTTP_400_BAD_REQUEST
            )

class AppleAuthView(generics.GenericAPIView):
    """
    API endpoint for Apple OAuth authentication.
    """
    serializer_class = AppleAuthSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Authenticate user with Apple ID token.
        """
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            auth_data = serializer.validated_data
            user = auth_data['user']
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            response_data = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': user,
                'created': auth_data.get('created', False),
                'linked': auth_data.get('linked', False)
            }
            
            # Use the response serializer for consistent formatting
            response_serializer = SocialAuthResponseSerializer(response_data)
            
            logger.info(f"Apple authentication successful for user: {user.email}")
            
            return Response(
                response_serializer.data,
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Apple authentication failed: {str(e)}")
            return Response(
                {"error": "Apple authentication failed. Please try again."},
                status=status.HTTP_400_BAD_REQUEST
            )

class SocialSignupView(generics.GenericAPIView):
    """
    Generic endpoint for social signup (can handle both Google and Apple).
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Handle social signup for both Google and Apple.
        """
        provider = request.data.get('provider')
        id_token = request.data.get('id_token')

        if not provider or not id_token:
            return Response(
                {"error": "Provider and id_token are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if provider not in ['google', 'apple']:
            return Response(
                {"error": "Invalid provider. Supported providers: google, apple"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            if provider == 'google':
                serializer = GoogleAuthSerializer(data={'id_token': id_token})
            elif provider == 'apple':
                serializer = AppleAuthSerializer(data={'id_token': id_token})

            serializer.is_valid(raise_exception=True)
            auth_data = serializer.validated_data
            user = auth_data['user']

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            response_data = {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': user,
                'created': auth_data.get('created', False),
                'linked': auth_data.get('linked', False),
                'provider': provider
            }

            response_serializer = SocialAuthResponseSerializer(response_data)
            
            logger.info(f"{provider.title()} signup successful for user: {user.email}")
            
            return Response(
                response_serializer.data,
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"{provider.title()} signup failed: {str(e)}")
            return Response(
                {"error": f"{provider.title()} signup failed. Please try again."},
                status=status.HTTP_400_BAD_REQUEST
            )

class LinkSocialAccountView(generics.GenericAPIView):
    """
    API endpoint to link social accounts to existing email accounts.
    """
    serializer_class = AccountLinkingSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Link a social account to the authenticated user's email account.
        """
        try:
            serializer = self.get_serializer(
                data=request.data, 
                context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            
            link_data = serializer.validated_data
            user = link_data['user']
            provider = link_data['provider']
            
            logger.info(f"Successfully linked {provider} account to user: {user.email}")
            
            return Response(
                {
                    "message": f"{provider.title()} account linked successfully.",
                    "user": UserProfileSerializer(user).data
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Account linking failed: {str(e)}")
            return Response(
                {"error": "Failed to link social account. Please try again."},
                status=status.HTTP_400_BAD_REQUEST
            )

class VerifyOtpView(generics.GenericAPIView):
    """
    API endpoint to verify OTP for email verification.
    """
    serializer_class = VerifyOtpSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"message": "OTP verified successfully. Account activated."},
            status=status.HTTP_200_OK,
        )

class LoginView(generics.GenericAPIView):
    """
    API endpoint for user login (email/password only).
    """
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)
        
        logger.info(f"Email login successful for user: {user.email}")
        
        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )

class ForgotPasswordView(generics.GenericAPIView):
    """
    API endpoint to initiate password reset.
    """
    serializer_class = ForgotPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"message": "OTP sent to your email for password reset."},
            status=status.HTTP_200_OK,
        )

class VerifyResetOtpView(generics.GenericAPIView):
    """
    API endpoint to verify OTP for password reset.
    """
    serializer_class = VerifyResetOtpSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"message": "OTP verified successfully. You can now reset your password."},
            status=status.HTTP_200_OK,
        )

class ResetPasswordView(generics.GenericAPIView):
    """
    API endpoint to reset user password.
    """
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            {"message": "Password reset successfully. You can now log in."},
            status=status.HTTP_200_OK,
        )

class UserProfileView(generics.RetrieveAPIView):
    """
    API endpoint to retrieve the authenticated user's profile.
    """
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        serializer = self.get_serializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def get_object(self):
        return self.request.user

class UpdateProfileView(generics.UpdateAPIView):
    """
    API endpoint to update user profile details.
    """
    serializer_class = UpdateProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        """
        Override update to handle social account restrictions.
        """
        user = self.get_object()
        
        # Check if trying to update restricted fields for social accounts
        if user.auth_provider != 'email' and 'email' in request.data:
            return Response(
                {"error": "Email cannot be updated for social accounts."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return super().update(request, *args, **kwargs)

class UpdateProfilePictureView(generics.UpdateAPIView):
    """
    API endpoint to update the user's profile picture.
    """
    serializer_class = UpdateProfilePictureSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

class ChangePasswordView(generics.GenericAPIView):
    """
    API endpoint to change the user's password.
    """
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        
        # Check if password change is available for this account type
        if user.auth_provider != 'email':
            return Response(
                {
                    "error": "Password change is not available for social accounts.",
                    "suggestion": "You can reset your password through your social provider."
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        logger.info(f"Password changed successfully for user: {user.email}")
        
        return Response(
            {"message": "Password changed successfully."},
            status=status.HTTP_200_OK,
        )

class UnlinkSocialAccountView(generics.GenericAPIView):
    """
    API endpoint to unlink social accounts from email accounts.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """
        Unlink a social account from the authenticated user.
        """
        user = request.user
        provider = request.data.get('provider')

        if not provider:
            return Response(
                {"error": "Provider is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if provider not in ['google', 'apple']:
            return Response(
                {"error": "Invalid provider. Supported providers: google, apple"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            if provider == 'google' and user.google_id:
                user.google_id = None
                # If this was the primary auth method, keep the account but require password reset
                if user.auth_provider == 'google':
                    user.auth_provider = 'email'
                    user.is_social_account = False
                    # User will need to set a password
                
            elif provider == 'apple' and user.apple_id:
                user.apple_id = None
                # If this was the primary auth method, keep the account but require password reset
                if user.auth_provider == 'apple':
                    user.auth_provider = 'email'
                    user.is_social_account = False
                    # User will need to set a password
            else:
                return Response(
                    {"error": f"No {provider} account is linked to this user."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user.save()
            
            logger.info(f"Successfully unlinked {provider} account from user: {user.email}")
            
            return Response(
                {
                    "message": f"{provider.title()} account unlinked successfully.",
                    "user": UserProfileSerializer(user).data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Failed to unlink {provider} account: {str(e)}")
            return Response(
                {"error": f"Failed to unlink {provider} account."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class UserAccountInfoView(generics.RetrieveAPIView):
    """
    API endpoint to get detailed account information including linked social accounts.
    """
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        
        account_info = {
            "user": UserProfileSerializer(user).data,
            "auth_provider": user.auth_provider,
            "is_social_account": user.is_social_account,
            "linked_accounts": {
                "google": bool(user.google_id),
                "apple": bool(user.apple_id)
            },
            "can_change_password": user.can_reset_password(),
            "has_password": user.has_usable_password()
        }
        
        return Response(account_info, status=status.HTTP_200_OK)

class CheckEmailView(generics.GenericAPIView):
    """
    API endpoint to check if an email exists and its authentication method.
    Useful for frontend to determine which login method to show.
    """
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        if not email:
            return Response(
                {"error": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = CustomUser.objects.get(email=email)
            
            return Response(
                {
                    "exists": True,
                    "auth_provider": user.auth_provider,
                    "is_verified": user.is_verified,
                    "is_social_account": user.is_social_account,
                    "has_password": user.has_usable_password(),
                    "linked_accounts": {
                        "google": bool(user.google_id),
                        "apple": bool(user.apple_id)
                    }
                },
                status=status.HTTP_200_OK
            )
            
        except CustomUser.DoesNotExist:
            return Response(
                {
                    "exists": False,
                    "message": "No account found with this email address."
                },
                status=status.HTTP_200_OK
            )