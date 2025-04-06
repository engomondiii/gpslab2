from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


class CustomUserAdmin(UserAdmin):
    """
    Custom admin class for managing the CustomUser model.
    """
    model = CustomUser
    list_display = (
        "username", 
        "email", 
        "is_verified", 
        "is_staff", 
        "registration_date"
    )  # Columns to display in the user list
    list_filter = ("is_verified", "is_staff", "is_superuser", "registration_date")  # Filters in the admin sidebar
    search_fields = ("username", "email", "first_name", "last_name")  # Searchable fields
    ordering = ("registration_date",)  # Default ordering of the users

    # Add and customize fields displayed in the user creation and editing forms
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Personal Info", {"fields": ("first_name", "last_name", "email", "profile_picture")}),
        ("Permissions", {"fields": ("is_verified", "is_staff", "is_superuser", "is_active", "groups", "user_permissions")}),
        ("Important Dates", {"fields": ("last_login", "registration_date")}),
        ("OTP Management", {"fields": ("otp", "otp_created_at", "reset_password_otp", "reset_password_otp_created_at")}),
    )

    # Fields displayed when creating a new user via the admin panel
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "password1", "password2", "first_name", "last_name", "is_verified"),
        }),
    )


# Register the CustomUser model with the CustomUserAdmin configuration
admin.site.register(CustomUser, CustomUserAdmin)
