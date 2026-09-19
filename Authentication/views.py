from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.db import transaction
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import RoleRequest
from .serializers import *

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

        current_site = request.get_host()

        activation_link = f"http://{current_site}" f"/account/activate/{uid}/{token}/"

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
        serializer.save(user=self.request.user)


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
        role_request.save(update_fields=["status"])

        return Response(
            {"detail": "Role request cancelled successfully."},
            status=status.HTTP_200_OK,
        )


class AdminRoleRequestListView(generics.ListAPIView):
    """
    Admin endpoint.

    Returns all role requests so administrators
    can review them.
    """

    serializer_class = AdminRoleRequestSerializer
    permission_classes = [IsAdminUser]
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


class AdminRoleRequestDetailView(generics.RetrieveAPIView):
    """
    Admin endpoint for viewing a specific role request.
    """

    serializer_class = AdminRoleRequestSerializer
    permission_classes = [IsAdminUser]
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


class AdminRoleRequestReviewView(generics.UpdateAPIView):
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
    permission_classes = [IsAdminUser]
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
