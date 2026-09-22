from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework import generics, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import RoleRequest, UserBase, UserRole
from .permissions import RolePermissionMixin
from .serializers import (AdminRoleRequestSerializer, RoleRequestSerializer,
                          UserBaseSerializer, UserTokenObtainSerializer)

UserBase = get_user_model()


class SignUpView(generics.CreateAPIView):
    """
    Create a new user account.

    Supports:
        - Member registration
        - Teacher role request
        - Author role request
        - Teacher + Author role requests
        - Role request attachments

    Account is created inactive and an activation email is sent.
    """

    serializer_class = UserBaseSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = []

    @transaction.atomic
    def create(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        user.is_active = False
        user.save(update_fields=["is_active"])

        token = default_token_generator.make_token(user)

        uid = urlsafe_base64_encode(force_bytes(user.pk))

        activation_link = f"{settings.BASE_URL}" f"/account/activate/{uid}/{token}/"

        send_mail(
            subject="Activate your PC-Lab account",
            message=(
                f"Hello {user.FName},\n\n"
                f"Your PC-Lab account has been created.\n\n"
                f"To activate your account, open the link below:\n\n"
                f"{activation_link}\n\n"
                f"If you did not create this account, you can ignore "
                f"this email."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.Email],
            fail_silently=False,
        )

        return Response(
            {
                "detail": (
                    "Account created successfully. "
                    "Please check your email to activate your account."
                ),
                "username": user.UserName,
                "email": user.Email,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(TokenObtainPairView):
    """
    Obtain JWT access and refresh tokens.

    Inactive accounts cannot log in.
    """

    serializer_class = UserTokenObtainSerializer


class LogOutView(generics.GenericAPIView):
    """
    Blacklist the supplied refresh token.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):

        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response(
                {"detail": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

        except TokenError:
            return Response(
                {"detail": "Invalid or expired refresh token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {"detail": "Logout successful."},
            status=status.HTTP_205_RESET_CONTENT,
        )


class ActivateAccountView(generics.GenericAPIView):
    """
    Activate a newly registered account through the
    UID + token sent by email.
    """

    permission_classes = []

    def get(self, request, uidb64, token):

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))

            user = UserBase.objects.get(pk=uid)

        except (
            TypeError,
            ValueError,
            OverflowError,
            UserBase.DoesNotExist,
        ):
            return Response(
                {"detail": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not default_token_generator.check_token(
            user,
            token,
        ):
            return Response(
                {"detail": ("Invalid or expired activation token.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_active:
            return Response(
                {"detail": "Account is already active."},
                status=status.HTTP_200_OK,
            )

        user.is_active = True
        user.save(update_fields=["is_active"])

        return Response(
            {"detail": "Account activated successfully."},
            status=status.HTTP_200_OK,
        )


class UserRoleRequestListCreateView(generics.ListCreateAPIView):
    """
    GET:
        Return the authenticated user's role requests.

    POST:
        Create a new Teacher or Author role request.
    """

    serializer_class = RoleRequestSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        return (
            RoleRequest.objects.filter(user=self.request.user)
            .prefetch_related("attachments")
            .select_related(
                "requested_role",
                "reviewer",
            )
            .order_by("-created_at")
        )

    def perform_create(self, serializer):
        serializer.save()


class UserRoleRequestDetailView(generics.RetrieveAPIView):
    """
    Retrieve one of the authenticated user's role requests.
    """

    serializer_class = RoleRequestSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    lookup_field = "pk"

    def get_queryset(self):
        return (
            RoleRequest.objects.filter(user=self.request.user)
            .prefetch_related("attachments")
            .select_related(
                "requested_role",
                "reviewer",
            )
        )


class UserRoleRequestCancelView(generics.GenericAPIView):
    """
    Cancel a pending role request belonging to
    the authenticated user.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, pk):

        try:
            role_request = RoleRequest.objects.get(
                pk=pk,
                user=request.user,
            )

        except RoleRequest.DoesNotExist:
            return Response(
                {"detail": "Role request not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if role_request.status != RoleRequest.Status.PENDING:
            return Response(
                {"detail": ("Only pending role requests " "can be cancelled.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        role_request.status = RoleRequest.Status.CANCELLED
        role_request.reviewed_at = timezone.now()

        role_request.save(update_fields=["status", "reviewed_at"])

        return Response(
            {"detail": "Role request cancelled successfully."},
            status=status.HTTP_200_OK,
        )


class UserRoleRemoveView(generics.GenericAPIView):
    """
    Remove a removable role from the authenticated user.

    Users can remove:
        - Teacher
        - Author

    Member and Admin roles cannot be removed.
    """

    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    REMOVABLE_ROLES = {
        "teacher": "Teacher",
        "author": "Author",
    }

    def delete(self, request, role_name):

        role_name = self.REMOVABLE_ROLES.get(role_name.lower())

        if not role_name:
            return Response(
                {"detail": ("Only Teacher and Author roles " "can be removed.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user_role = UserRole.objects.get(
                user=request.user,
                role__name=role_name,
            )

        except UserRole.DoesNotExist:
            return Response(
                {"detail": (f"You do not have the {role_name} role.")},
                status=status.HTTP_404_NOT_FOUND,
            )

        user_role.delete()

        return Response(
            {"detail": (f"{role_name} role removed successfully.")},
            status=status.HTTP_200_OK,
        )


class AdminRoleRequestListView(RolePermissionMixin, generics.ListAPIView):
    """
    Admin endpoint.

    Returns all role requests so administrators
    can review them.
    """

    serializer_class = AdminRoleRequestSerializer
    permission_classes = ["Admin"]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):

        queryset = (
            RoleRequest.objects.all()
            .select_related(
                "user",
                "requested_role",
                "reviewer",
            )
            .prefetch_related("attachments")
            .order_by("-created_at")
        )

        # ----------------------------------------------------
        # Optional status filtering
        #
        # Example:
        # /account/admin/role-requests/?status=Pending
        # ----------------------------------------------------

        request_status = self.request.query_params.get("status")

        if request_status:
            queryset = queryset.filter(status=request_status)

        return queryset


class AdminRoleRequestDetailView(RolePermissionMixin, generics.RetrieveAPIView):
    """
    Admin endpoint for viewing a specific role request.
    """

    serializer_class = AdminRoleRequestSerializer
    permission_classes = ["Admin"]
    authentication_classes = [JWTAuthentication]

    queryset = (
        RoleRequest.objects.all()
        .select_related(
            "user",
            "requested_role",
            "reviewer",
        )
        .prefetch_related("attachments")
    )


class AdminRoleRequestReviewView(RolePermissionMixin, generics.UpdateAPIView):
    """
    Admin endpoint used to approve or reject
    a pending role request.

    Expected data:

        {
            "status": "Approved",
            "review_note": "Welcome!"
        }

    or:

        {
            "status": "Rejected",
            "review_note": "More information is required."
        }
    """

    serializer_class = AdminRoleRequestSerializer
    permission_classes = ["Admin"]
    authentication_classes = [JWTAuthentication]

    queryset = (
        RoleRequest.objects.all()
        .select_related(
            "user",
            "requested_role",
            "reviewer",
        )
        .prefetch_related("attachments")
    )

    @transaction.atomic
    def update(self, request, *args, **kwargs):

        role_request = self.get_object()

        if role_request.status != RoleRequest.Status.PENDING:
            return Response(
                {"detail": ("Only pending role requests " "can be reviewed.")},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = self.get_serializer(
            role_request,
            data=request.data,
            partial=True,
        )

        serializer.is_valid(raise_exception=True)

        serializer.save(reviewer=request.user)

        return Response(
            serializer.data,
            status=status.HTTP_200_OK,
        )


class GoogleAuthView(APIView):
    """
    Authenticate a user using a Google ID token.

    Flow:
    1. Receive Google's ID token.
    2. Verify the token with Google.
    3. Extract the Google account information.
    4. Find an existing user by google_id.
    5. Create a new user if necessary.
    6. Return our application's JWT access + refresh tokens.
    """

    def post(self, request):
        google_token = request.data.get("id_token")

        if not google_token:
            return Response(
                {"error": "توکن گوگل ارسال نشده است."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            decoded = id_token.verify_oauth2_token(
                google_token,
                requests.Request(),
                settings.GOOGLE_CLIENT_ID,
            )

        except ValueError:
            return Response(
                {"error": "توکن گوگل نامعتبر یا منقضی شده است."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        google_id = decoded.get("sub")
        email = decoded.get("email")
        email_verified = decoded.get("email_verified", False)

        if not google_id or not email:
            return Response(
                {"error": "اطلاعات حساب گوگل ناقص است."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        given_name = decoded.get("given_name", "")
        family_name = decoded.get("family_name", "")

        full_name = f"{given_name} {family_name}".strip()

        if not full_name:
            full_name = email.split("@")[0]

        if not email_verified:
            return Response(
                {"error": "ایمیل حساب گوگل تأیید نشده است."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = UserBase.objects.filter(google_id=google_id).first()
        
        if user and not user.is_active:
            return Response(
                {"error": "این حساب غیرفعال است."},
                status=status.HTTP_403_FORBIDDEN,
            )

        created = False

        if user:
            if full_name and user.FName != full_name:
                user.FName = full_name
                user.save(update_fields=["FName"])

        # -----------------------------------------
        # New Google account
        # -----------------------------------------

        else:
            # Check whether the email already belongs
            # to an existing normal account.
            existing_user = UserBase.objects.filter(Email__iexact=email).first()

            if existing_user:
                return Response(
                    {"error": ("این ایمیل قبلاً در سایت ثبت شده است. ")},
                    status=status.HTTP_409_CONFLICT,
                )

            base_username = email.split("@")[0]
            username = base_username

            counter = 1

            while UserBase.objects.filter(UserName=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            user = UserBase.objects.create_user(
                UserName=username,
                Email=email,
                FName=full_name,
                google_id=google_id,
            )

            created = True

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "is_new_user": created,
            },
            status=status.HTTP_200_OK,
        )
