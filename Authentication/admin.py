from django.contrib import admin

from .models import *


@admin.register(UserBase)
class UserBaseAdmin(admin.ModelAdmin):
    list_display = (
        "UserName",
        "FName",
        "Email",
        "is_active",
        "is_staff",
        "is_superuser",
    )
    search_fields = (
        "UserName",
        "FName",
        "Email",
    )
    list_filter = (
        "is_active",
        "is_staff",
        "is_superuser",
    )


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    search_fields = ("name",)


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ("user", "role")
    search_fields = (
        "user__UserName",
        "role__name",
    )
    list_filter = ("role",)


@admin.register(RoleRequest)
class RoleRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "requested_role",
        "status",
        "reviewer",
        "created_at",
        "reviewed_at",
    )
    search_fields = (
        "user__UserName",
        "user__Email",
        "requested_role__name",
    )
    list_filter = (
        "status",
        "requested_role",
    )
    readonly_fields = (
        "created_at",
        "reviewed_at",
    )


@admin.register(RoleRequestAttachment)
class RoleRequestAttachmentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "request",
        "uploaded_at",
        "file",
    )
    search_fields = (
        "request__user__UserName",
        "request__user__Email",
    )
    readonly_fields = ("uploaded_at",)
