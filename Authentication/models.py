from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
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

        return self.create_user(UserName, password, **extra_fields)


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
