from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models


class CustomUserManager(BaseUserManager):

    def create_user(self, UserName, password=None, **extra_fields):
        if not UserName:
            raise ValueError("UserName is required.")

        user = self.model(UserName=UserName, **extra_fields)

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, UserName, password=None, **extra_fields):
        extra_fields["is_staff"] = True
        extra_fields["is_superuser"] = True
        extra_fields["is_active"] = True

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        user = self.create_user(UserName, password, **extra_fields)

        admin_role = Role.objects.get(name="Admin")

        UserRole.objects.get_or_create(user=user, role=admin_role)

        member_role = Role.objects.get(name="Member")

        UserRole.objects.get_or_create(user=user, role=member_role)

        return user


class Role(models.Model):
    name = models.CharField(max_length=20, unique=True)

    def __str__(self):
        return self.name


class UserBase(AbstractBaseUser, PermissionsMixin):
    UserName = models.CharField(max_length=85, unique=True)
    FName = models.CharField(max_length=75)
    Email = models.EmailField(max_length=150, blank=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = "UserName"
    REQUIRED_FIELDS = ["FName", "Email"]
    objects = CustomUserManager()

    def __str__(self):
        return self.UserName


class UserRole(models.Model):

    user = models.ForeignKey(
        UserBase, on_delete=models.CASCADE, related_name="user_roles"
    )

    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="user_roles")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "role"], name="unique_user_role")
        ]

    def __str__(self):
        return f"{self.user.UserName} - {self.role.name}"
