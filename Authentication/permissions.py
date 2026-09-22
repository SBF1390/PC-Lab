from rest_framework.permissions import BasePermission

from .models import UserRole


def IsRole(role_name):
    """
    Create a permission class that allows access only to
    authenticated users who have the specified role.

    Example:
        permission_classes = ["Teacher"]
    """

    class RolePermission(BasePermission):
        def has_permission(self, request, view):
            user = request.user

            if not user or not user.is_authenticated:
                return False

            return UserRole.objects.filter(
                user=user,
                role__name=role_name,
            ).exists()

    RolePermission.__name__ = f"IsRole_{role_name}"

    return RolePermission


def IsAnyRole(*role_names):
    """
    Create a permission class that allows access if the
    authenticated user has at least one of the given roles.

    Example:
        permission_classes = [IsAnyRole("Teacher", "Author")]
    """

    class AnyRolePermission(BasePermission):
        def has_permission(self, request, view):
            user = request.user

            if not user or not user.is_authenticated:
                return False

            return UserRole.objects.filter(
                user=user,
                role__name__in=role_names,
            ).exists()

    AnyRolePermission.__name__ = "IsAnyRole_" + "_".join(role_names)

    return AnyRolePermission


class RolePermissionMixin:
    """
    Allows role names to be used directly inside
    permission_classes.

    Example:

        permission_classes = ["Teacher"]

    The mixin converts "Teacher" into:

        IsRole("Teacher")
    """

    def get_permissions(self):
        permissions = []

        for permission in self.permission_classes:

            if isinstance(permission, str):
                permission_class = IsRole(permission)
            else:
                permission_class = permission

            permissions.append(permission_class())

        return permissions
