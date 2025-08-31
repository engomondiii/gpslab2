from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    Admin configuration for CustomUser aligned with the updated model.
    Includes social auth fields, OTP fields, and profile picture preview.
    """
    model = CustomUser

    # List page
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "auth_provider",
        "is_social_account",
        "is_verified",
        "is_staff",
        "registration_date",
    )
    list_filter = (
        "auth_provider",
        "is_social_account",
        "is_verified",
        "is_staff",
        "is_superuser",
        "groups",
        "registration_date",
    )
    search_fields = (
        "username",
        "email",
        "first_name",
        "last_name",
        "google_id",
        "apple_id",
    )
    ordering = ("-registration_date",)

    # Make some fields read-only in the detail page
    readonly_fields = (
        "registration_date",
        "last_login",
        "date_joined",
        "social_id",
        "profile_picture_preview",
    )

    # Field layout in the detail page
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            "Personal Info",
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "email",
                    "profile_picture",
                    "profile_picture_preview",
                )
            },
        ),
        (
            "Social Authentication",
            {
                "classes": ("collapse",),
                "fields": (
                    "auth_provider",
                    "is_social_account",
                    "social_id",
                    "google_id",
                    "apple_id",
                    "social_profile_picture_url",
                ),
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_verified",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Important Dates",
            {"fields": ("last_login", "date_joined", "registration_date")},
        ),
        (
            "OTP Management",
            {
                "classes": ("collapse",),
                "fields": (
                    "otp",
                    "otp_created_at",
                    "reset_password_otp",
                    "reset_password_otp_created_at",
                ),
            },
        ),
    )

    # Fields for the "Add user" form
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "password1",
                    "password2",
                    "first_name",
                    "last_name",
                    "is_verified",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                ),
            },
        ),
    )

    filter_horizontal = ("groups", "user_permissions")

    def profile_picture_preview(self, obj):
        """
        Show a small preview of the profile picture in the admin detail page.
        """
        url = obj.get_profile_picture_url()
        if url:
            return format_html('<img src="{}" style="height:60px;width:60px;object-fit:cover;border-radius:6px;" />', url)
        return "—"
    profile_picture_preview.short_description = "Profile Picture Preview"
