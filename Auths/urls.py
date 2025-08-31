from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    # Auth basics
    RegisterView,
    VerifyOtpView,
    LoginView,

    # Social auth
    GoogleAuthView,
    AppleAuthView,
    SocialSignupView,
    LinkSocialAccountView,
    UnlinkSocialAccountView,

    # Profile & account
    UserProfileView,
    UpdateProfileView,
    UpdateProfilePictureView,
    ChangePasswordView,
    UserAccountInfoView,
    CheckEmailView,

    # Password reset
    ForgotPasswordView,
    VerifyResetOtpView,
    ResetPasswordView,
)

urlpatterns = [
    # Auth basics
    path('signup/', RegisterView.as_view(), name='signup'),
    path('verify-otp/', VerifyOtpView.as_view(), name='verify_otp'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Social auth (frontend sends ID token here)
    path('google/', GoogleAuthView.as_view(), name='google_auth'),
    path('apple/', AppleAuthView.as_view(), name='apple_auth'),
    path('social-signup/', SocialSignupView.as_view(), name='social_signup'),
    path('link-social/', LinkSocialAccountView.as_view(), name='link_social'),
    path('unlink-social/', UnlinkSocialAccountView.as_view(), name='unlink_social'),

    # Profile & account
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('profile/update/', UpdateProfileView.as_view(), name='update_profile'),
    path('profile/update-picture/', UpdateProfilePictureView.as_view(), name='update_profile_picture'),
    path('profile/change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('account/', UserAccountInfoView.as_view(), name='account_info'),
    path('check-email/', CheckEmailView.as_view(), name='check_email'),

    # Password reset
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('verify-reset-otp/', VerifyResetOtpView.as_view(), name='verify_reset_otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
]
