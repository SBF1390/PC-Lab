import shutil
import tempfile
from datetime import timedelta
from unittest.mock import ANY, patch
from uuid import uuid4

from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient
from rest_framework.views import APIView
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from .models import Role, RoleRequest, RoleRequestAttachment, UserBase, UserRole
from .permissions import IsAnyRole, IsRole, RolePermissionMixin

# ----------------------------------------------------------------------
# Temporary media directory for uploaded-file tests
# ----------------------------------------------------------------------

TEST_MEDIA_ROOT = tempfile.mkdtemp(prefix="pc_lab_test_media_")


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ALLOWED_HOSTS=[
        "testserver",
        "localhost",
        "127.0.0.1",
    ],
    MEDIA_ROOT=TEST_MEDIA_ROOT,
)
class AuthenticationTests(TestCase):

    PASSWORD = "TestPassword123!Secure"

    # ------------------------------------------------------------------
    # Setup / cleanup
    # ------------------------------------------------------------------

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(
            TEST_MEDIA_ROOT,
            ignore_errors=True,
        )

    def setUp(self):
        self.client = APIClient()
        self.request_factory = RequestFactory()

        self.member_role = Role.objects.get_or_create(name="Member")[0]

        self.teacher_role = Role.objects.get_or_create(name="Teacher")[0]

        self.author_role = Role.objects.get_or_create(name="Author")[0]

        self.admin_role = Role.objects.get_or_create(name="Admin")[0]

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def signup_data(
        self,
        username=None,
        email=None,
        role_request="None",
        teacher_description=None,
        author_description=None,
        teacher_attachments=None,
        author_attachments=None,
    ):
        data = {
            "UserName": username or f"user_{uuid4().hex[:8]}",
            "FName": "Test User",
            "Email": email or f"{uuid4().hex[:8]}@example.com",
            "password": self.PASSWORD,
            "role_request": role_request,
        }

        if teacher_description is not None:
            data["teacher_description"] = teacher_description

        if author_description is not None:
            data["author_description"] = author_description

        if teacher_attachments:
            data["teacher_attachments"] = teacher_attachments

        if author_attachments:
            data["author_attachments"] = author_attachments

        return data

    def activate_user(self, user):
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        return self.client.get(f"/account/activate/{uidb64}/{token}/")

    def login_user(self, username, password=None):
        return self.client.post(
            "/account/login/",
            {
                "UserName": username,
                "password": password or self.PASSWORD,
            },
            format="json",
        )

    def authenticate(self, access_token):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

    def create_active_user(
        self,
        username=None,
        email=None,
        first_name="Test User",
    ):
        user = UserBase.objects.create_user(
            UserName=username or f"user_{uuid4().hex[:8]}",
            password=self.PASSWORD,
            FName=first_name,
            Email=email or f"{uuid4().hex[:8]}@example.com",
        )

        user.is_active = True
        user.save(update_fields=["is_active"])

        return user

    def create_admin(self):
        return UserBase.objects.create_superuser(
            UserName=f"admin_{uuid4().hex[:8]}",
            password=self.PASSWORD,
            FName="Admin",
            Email=f"{uuid4().hex[:8]}@example.com",
        )

    def create_role_request(
        self,
        user,
        role,
        description="Test role request.",
    ):
        return RoleRequest.objects.create(
            user=user,
            requested_role=role,
            description=description,
        )

    def create_uploaded_file(
        self,
        name="test.txt",
        content=b"test file content",
        content_type="text/plain",
    ):
        return SimpleUploadedFile(
            name,
            content,
            content_type=content_type,
        )

    def google_payload(
        self,
        *,
        google_id="google-sub-123",
        email="google@example.com",
        email_verified=True,
        given_name="Google",
        family_name="User",
    ):
        return {
            "sub": google_id,
            "email": email,
            "email_verified": email_verified,
            "given_name": given_name,
            "family_name": family_name,
        }

    # ==================================================================
    # MODEL / MANAGER TESTS
    # ==================================================================

    def test_default_roles_exist(self):
        self.assertEqual(
            Role.objects.count(),
            4,
        )

        self.assertTrue(Role.objects.filter(name="Member").exists())

        self.assertTrue(Role.objects.filter(name="Teacher").exists())

        self.assertTrue(Role.objects.filter(name="Author").exists())

        self.assertTrue(Role.objects.filter(name="Admin").exists())

    def test_role_names_are_unique(self):
        with self.assertRaises(Exception):
            Role.objects.create(name="Member")

    def test_normal_user_automatically_gets_member_role(self):
        user = UserBase.objects.create_user(
            UserName="member_user",
            password=self.PASSWORD,
            FName="Member",
            Email="member@example.com",
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.member_role,
            ).exists()
        )

    def test_normal_user_does_not_get_admin_role(self):
        user = UserBase.objects.create_user(
            UserName="normal_user",
            password=self.PASSWORD,
            FName="Normal",
            Email="normal@example.com",
        )

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.admin_role,
            ).exists()
        )

    def test_create_user_requires_username(self):
        with self.assertRaises(ValueError):
            UserBase.objects.create_user(
                UserName="",
                password=self.PASSWORD,
                FName="No Username",
                Email="nousername@example.com",
            )

    def test_create_superuser_gets_member_and_admin_roles(self):
        admin = self.create_admin()

        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.is_active)

        self.assertTrue(
            UserRole.objects.filter(
                user=admin,
                role=self.member_role,
            ).exists()
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=admin,
                role=self.admin_role,
            ).exists()
        )

    def test_superuser_requires_is_staff(self):
        with self.assertRaises(ValueError):
            UserBase.objects.create_superuser(
                UserName="bad_admin_1",
                password=self.PASSWORD,
                FName="Bad Admin",
                Email="badadmin1@example.com",
                is_staff=False,
            )

    def test_superuser_requires_is_superuser(self):
        with self.assertRaises(ValueError):
            UserBase.objects.create_superuser(
                UserName="bad_admin_2",
                password=self.PASSWORD,
                FName="Bad Admin",
                Email="badadmin2@example.com",
                is_superuser=False,
            )

    def test_password_is_hashed(self):
        user = UserBase.objects.create_user(
            UserName="hashed_user",
            password=self.PASSWORD,
            FName="Hashed",
            Email="hashed@example.com",
        )

        self.assertNotEqual(
            user.password,
            self.PASSWORD,
        )

        self.assertTrue(user.check_password(self.PASSWORD))

    def test_user_string_representation(self):
        user = self.create_active_user(username="string_user")

        self.assertEqual(
            str(user),
            "string_user",
        )

    def test_user_role_string_representation(self):
        user = self.create_active_user(username="role_string_user")

        user_role = UserRole.objects.get_or_create(
            user=user,
            role=self.teacher_role,
        )[0]

        self.assertEqual(
            str(user_role),
            "role_string_user - Teacher",
        )

    def test_role_request_string_representation(self):
        user = self.create_active_user(username="request_string_user")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        self.assertEqual(
            str(role_request),
            "request_string_user - Teacher - Pending",
        )

    def test_attachment_string_representation(self):
        user = self.create_active_user(username="attachment_string_user")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        attachment = RoleRequestAttachment.objects.create(
            request=role_request,
            file=self.create_uploaded_file(),
        )

        self.assertEqual(
            str(attachment),
            f"attachment_string_user - Attachment {attachment.id}",
        )

    def test_duplicate_user_role_is_prevented(self):
        user = self.create_active_user()

        UserRole.objects.create(
            user=user,
            role=self.teacher_role,
        )

        with self.assertRaises(Exception):
            UserRole.objects.create(
                user=user,
                role=self.teacher_role,
            )

    # ==================================================================
    # SIGNUP TESTS
    # ==================================================================

    def test_signup_creates_inactive_member(self):
        data = self.signup_data()

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.assertFalse(user.is_active)

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.member_role,
            ).exists()
        )

        self.assertFalse(RoleRequest.objects.filter(user=user).exists())

    def test_signup_response_contains_username_and_email(self):
        data = self.signup_data()

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            response.data["username"],
            data["UserName"],
        )

        self.assertEqual(
            response.data["email"],
            data["Email"],
        )

    def test_signup_sends_activation_email(self):
        data = self.signup_data()

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            len(mail.outbox),
            1,
        )

        email = mail.outbox[0]

        self.assertEqual(
            email.to,
            [data["Email"]],
        )

        self.assertEqual(
            email.subject,
            "Activate your PC-Lab account",
        )

        self.assertIn(
            "Your PC-Lab account has been created.",
            email.body,
        )

        self.assertIn(
            "/account/activate/",
            email.body,
        )

    def test_signup_uses_base_url_in_activation_link(self):
        data = self.signup_data()

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            len(mail.outbox),
            1,
        )

        self.assertIn(
            f"{settings.BASE_URL}/account/activate/",
            mail.outbox[0].body,
        )

    def test_signup_none_creates_no_role_request(self):
        data = self.signup_data(role_request="None")

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.assertEqual(
            RoleRequest.objects.filter(user=user).count(),
            0,
        )

    def test_teacher_signup_creates_pending_teacher_request(self):
        data = self.signup_data(
            role_request="Teacher",
            teacher_description=("I want to become a programming teacher."),
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        role_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.PENDING,
        )

        self.assertEqual(
            role_request.description,
            data["teacher_description"],
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.member_role,
            ).exists()
        )

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.teacher_role,
            ).exists()
        )

    def test_author_signup_creates_pending_author_request(self):
        data = self.signup_data(
            role_request="Author",
            author_description=("I want to become an author."),
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        role_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.author_role,
        )

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.PENDING,
        )

        self.assertEqual(
            role_request.description,
            data["author_description"],
        )

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.author_role,
            ).exists()
        )

    def test_both_signup_creates_two_requests(self):
        data = self.signup_data(
            role_request="Both",
            teacher_description="Teacher application.",
            author_description="Author application.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.assertEqual(
            RoleRequest.objects.filter(user=user).count(),
            2,
        )

        teacher_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        author_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.author_role,
        )

        self.assertEqual(
            teacher_request.description,
            data["teacher_description"],
        )

        self.assertEqual(
            author_request.description,
            data["author_description"],
        )

    def test_teacher_signup_requires_description(self):
        data = self.signup_data(role_request="Teacher")

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertFalse(UserBase.objects.filter(UserName=data["UserName"]).exists())

    def test_author_signup_requires_description(self):
        data = self.signup_data(role_request="Author")

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertFalse(UserBase.objects.filter(UserName=data["UserName"]).exists())

    def test_both_signup_requires_teacher_description(self):
        data = self.signup_data(
            role_request="Both",
            author_description="Author application.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_both_signup_requires_author_description(self):
        data = self.signup_data(
            role_request="Both",
            teacher_description="Teacher application.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_none_rejects_teacher_description(self):
        data = self.signup_data(
            role_request="None",
            teacher_description="Not allowed.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_none_rejects_author_description(self):
        data = self.signup_data(
            role_request="None",
            author_description="Not allowed.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_none_rejects_teacher_attachments(self):
        data = self.signup_data(
            role_request="None",
            teacher_attachments=[self.create_uploaded_file()],
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_none_rejects_author_attachments(self):
        data = self.signup_data(
            role_request="None",
            author_attachments=[self.create_uploaded_file()],
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_teacher_choice_rejects_author_description(self):
        data = self.signup_data(
            role_request="Teacher",
            teacher_description="Teacher application.",
            author_description="Not allowed.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_teacher_choice_rejects_author_attachments(self):
        data = self.signup_data(
            role_request="Teacher",
            teacher_description="Teacher application.",
            author_attachments=[self.create_uploaded_file()],
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_author_choice_rejects_teacher_description(self):
        data = self.signup_data(
            role_request="Author",
            author_description="Author application.",
            teacher_description="Not allowed.",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_author_choice_rejects_teacher_attachments(self):
        data = self.signup_data(
            role_request="Author",
            author_description="Author application.",
            teacher_attachments=[self.create_uploaded_file()],
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_role_request_choice_is_rejected(self):
        data = self.signup_data(role_request="Admin")

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_signup_rejects_duplicate_username(self):
        username = "duplicate_username"

        self.create_active_user(
            username=username,
            email="first@example.com",
        )

        data = self.signup_data(
            username=username,
            email="second@example.com",
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_signup_rejects_duplicate_email(self):
        email = "duplicate@example.com"

        self.create_active_user(
            username="first_email_user",
            email=email,
        )

        data = self.signup_data(
            username="second_email_user",
            email=email,
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_signup_supports_teacher_attachment(self):
        teacher_file = self.create_uploaded_file(
            name="teacher.txt",
            content=b"teacher document",
        )

        data = self.signup_data(
            role_request="Teacher",
            teacher_description="Teacher application.",
            teacher_attachments=[teacher_file],
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        role_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        self.assertEqual(
            role_request.attachments.count(),
            1,
        )

        attachment = role_request.attachments.first()

        self.assertIsNotNone(attachment)

        self.assertTrue(attachment.file.name.startswith("role_requests/"))

    def test_signup_supports_multiple_teacher_attachments(self):
        files = [
            self.create_uploaded_file(
                name="teacher1.txt",
                content=b"teacher 1",
            ),
            self.create_uploaded_file(
                name="teacher2.txt",
                content=b"teacher 2",
            ),
        ]

        data = self.signup_data(
            role_request="Teacher",
            teacher_description="Teacher application.",
            teacher_attachments=files,
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        role_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        self.assertEqual(
            role_request.attachments.count(),
            2,
        )

    def test_signup_supports_both_role_attachments(self):
        teacher_file = self.create_uploaded_file(
            name="teacher.txt",
            content=b"teacher",
        )

        author_file = self.create_uploaded_file(
            name="author.txt",
            content=b"author",
        )

        data = self.signup_data(
            role_request="Both",
            teacher_description="Teacher application.",
            author_description="Author application.",
            teacher_attachments=[teacher_file],
            author_attachments=[author_file],
        )

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        teacher_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        author_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.author_role,
        )

        self.assertEqual(
            teacher_request.attachments.count(),
            1,
        )

        self.assertEqual(
            author_request.attachments.count(),
            1,
        )

    # ==================================================================
    # ACTIVATION TESTS
    # ==================================================================

    def test_activation_activates_user(self):
        data = self.signup_data()

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.assertFalse(user.is_active)

        activation_response = self.activate_user(user)

        self.assertEqual(
            activation_response.status_code,
            status.HTTP_200_OK,
        )

        user.refresh_from_db()

        self.assertTrue(user.is_active)

    def test_activation_returns_success_message(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        response = self.activate_user(user)

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            response.data["detail"],
            "Account activated successfully.",
        )

    def test_already_active_account_returns_success(self):
        user = self.create_active_user()

        response = self.activate_user(user)

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            response.data["detail"],
            "Account is already active.",
        )

    def test_invalid_activation_uid_fails(self):
        response = self.client.get("/account/activate/not-valid/some-token/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertEqual(
            response.data["detail"],
            "Invalid activation link.",
        )

    def test_nonexistent_activation_uid_fails(self):
        invalid_uid = urlsafe_base64_encode(force_bytes(999999999))

        response = self.client.get(f"/account/activate/{invalid_uid}/some-token/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_activation_token_fails(self):
        user = UserBase.objects.create_user(
            UserName="invalid_token_user",
            password=self.PASSWORD,
            FName="Invalid Token",
            Email="invalidtoken@example.com",
        )

        user.is_active = False
        user.save(update_fields=["is_active"])

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        response = self.client.get(f"/account/activate/{uidb64}/wrong-token/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertEqual(
            response.data["detail"],
            "Invalid or expired activation token.",
        )

        user.refresh_from_db()

        self.assertFalse(user.is_active)

    # ==================================================================
    # LOGIN / JWT TESTS
    # ==================================================================

    def test_active_user_can_login(self):
        user = self.create_active_user(username="login_user")

        response = self.login_user(user.UserName)

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertIn(
            "access",
            response.data,
        )

        self.assertIn(
            "refresh",
            response.data,
        )

    def test_inactive_user_cannot_login(self):
        user = UserBase.objects.create_user(
            UserName="inactive_login",
            password=self.PASSWORD,
            FName="Inactive",
            Email="inactive@example.com",
        )

        user.is_active = False
        user.save(update_fields=["is_active"])

        response = self.login_user(user.UserName)

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_wrong_password_fails(self):
        user = self.create_active_user(username="wrong_password")

        response = self.login_user(
            user.UserName,
            "CompletelyWrongPassword123!",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_wrong_username_fails(self):
        response = self.login_user("does_not_exist")

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_refresh_token_works(self):
        user = self.create_active_user(username="refresh_user")

        login_response = self.login_user(user.UserName)

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        response = self.client.post(
            "/account/token/refresh/",
            {"refresh": login_response.data["refresh"]},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertIn(
            "access",
            response.data,
        )

    def test_refresh_requires_refresh_token(self):
        response = self.client.post(
            "/account/token/refresh/",
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_refresh_token_fails(self):
        response = self.client.post(
            "/account/token/refresh/",
            {"refresh": "invalid-refresh-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    # ==================================================================
    # LOGOUT TESTS
    # ==================================================================

    def test_logout_requires_authentication(self):
        response = self.client.post(
            "/account/logout/",
            {"refresh": "anything"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_logout_requires_refresh_token(self):
        user = self.create_active_user(username="logout_missing_refresh")

        login_response = self.login_user(user.UserName)

        self.authenticate(login_response.data["access"])

        response = self.client.post(
            "/account/logout/",
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_logout_blacklists_refresh_token(self):
        user = self.create_active_user(username="logout_user")

        login_response = self.login_user(user.UserName)

        self.authenticate(login_response.data["access"])

        refresh_token = login_response.data["refresh"]

        response = self.client.post(
            "/account/logout/",
            {"refresh": refresh_token},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_205_RESET_CONTENT,
        )

        self.assertEqual(
            BlacklistedToken.objects.count(),
            1,
        )

        refresh_response = self.client.post(
            "/account/token/refresh/",
            {"refresh": refresh_token},
            format="json",
        )

        self.assertEqual(
            refresh_response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_invalid_logout_refresh_token_fails(self):
        user = self.create_active_user(username="logout_invalid")

        login_response = self.login_user(user.UserName)

        self.authenticate(login_response.data["access"])

        response = self.client.post(
            "/account/logout/",
            {"refresh": "invalid-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_logout_response_message(self):
        user = self.create_active_user(username="logout_message")

        login_response = self.login_user(user.UserName)

        self.authenticate(login_response.data["access"])

        response = self.client.post(
            "/account/logout/",
            {"refresh": login_response.data["refresh"]},
            format="json",
        )

        self.assertEqual(
            response.data["detail"],
            "Logout successful.",
        )

    # ==================================================================
    # USER ROLE REQUEST TESTS
    # ==================================================================

    def test_unauthenticated_user_cannot_access_role_requests(self):
        response = self.client.get("/account/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_authenticated_user_can_create_teacher_request(self):
        user = self.create_active_user(username="teacher_request_user")

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Teacher request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertTrue(
            RoleRequest.objects.filter(
                user=user,
                requested_role=self.teacher_role,
                status=RoleRequest.Status.PENDING,
            ).exists()
        )

    def test_authenticated_user_can_create_author_request(self):
        user = self.create_active_user(username="author_request_user")

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Author",
                "description": "Author request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertTrue(
            RoleRequest.objects.filter(
                user=user,
                requested_role=self.author_role,
                status=RoleRequest.Status.PENDING,
            ).exists()
        )

    def test_role_request_requires_description(self):
        user = self.create_active_user(username="missing_description")

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {"requested_role": "Teacher"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_invalid_role_cannot_be_requested(self):
        user = self.create_active_user(username="invalid_role_request")

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Admin",
                "description": "Admin request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_existing_role_cannot_be_requested(self):
        user = self.create_active_user(username="existing_role")

        UserRole.objects.get_or_create(
            user=user,
            role=self.teacher_role,
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Existing teacher role.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_duplicate_pending_role_request_is_rejected(self):
        user = self.create_active_user(username="duplicate_pending")

        self.create_role_request(
            user,
            self.teacher_role,
            "First request.",
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Second request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_teacher_and_author_pending_requests_are_independent(self):
        user = self.create_active_user(username="independent_requests")

        self.client.force_authenticate(user=user)

        teacher_response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Teacher request.",
            },
            format="json",
        )

        author_response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Author",
                "description": "Author request.",
            },
            format="json",
        )

        self.assertEqual(
            teacher_response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            author_response.status_code,
            status.HTTP_201_CREATED,
        )

        self.assertEqual(
            RoleRequest.objects.filter(user=user).count(),
            2,
        )

    def test_user_can_list_own_role_requests(self):
        user = self.create_active_user(username="list_requests")

        own_request = self.create_role_request(
            user,
            self.teacher_role,
            "My request.",
        )

        other_user = self.create_active_user(
            username="other_list_user",
            email="other_list@example.com",
        )

        self.create_role_request(
            other_user,
            self.author_role,
            "Other request.",
        )

        self.client.force_authenticate(user=user)

        response = self.client.get("/account/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

        self.assertEqual(
            response.data[0]["id"],
            own_request.id,
        )

    def test_user_can_view_own_role_request_detail(self):
        user = self.create_active_user(username="own_detail")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "My detail request.",
        )

        self.client.force_authenticate(user=user)

        response = self.client.get(f"/account/role-requests/{role_request.pk}/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            response.data["id"],
            role_request.id,
        )

        self.assertEqual(
            response.data["requested_role"],
            "Teacher",
        )

    def test_user_cannot_view_another_users_role_request(self):
        user = self.create_active_user(username="detail_owner")

        other_user = self.create_active_user(
            username="detail_other",
            email="detail_other@example.com",
        )

        role_request = self.create_role_request(
            other_user,
            self.teacher_role,
            "Other request.",
        )

        self.client.force_authenticate(user=user)

        response = self.client.get(f"/account/role-requests/{role_request.pk}/")

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_user_can_create_role_request_with_attachment(self):
        user = self.create_active_user(username="request_attachment")

        self.client.force_authenticate(user=user)

        uploaded_file = self.create_uploaded_file(name="certificate.txt")

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Teacher with attachment.",
                "attachments": [uploaded_file],
            },
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        role_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        self.assertEqual(
            role_request.attachments.count(),
            1,
        )

    def test_user_can_create_role_request_with_multiple_attachments(self):
        user = self.create_active_user(username="multiple_request_attachments")

        self.client.force_authenticate(user=user)

        files = [
            self.create_uploaded_file(name="file1.txt"),
            self.create_uploaded_file(name="file2.txt"),
        ]

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Author",
                "description": "Author with attachments.",
                "attachments": files,
            },
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

        role_request = RoleRequest.objects.get(
            user=user,
            requested_role=self.author_role,
        )

        self.assertEqual(
            role_request.attachments.count(),
            2,
        )

    def test_user_role_request_attachment_urls_are_returned(self):
        user = self.create_active_user(username="attachment_urls")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "Attachment URL request.",
        )

        RoleRequestAttachment.objects.create(
            request=role_request,
            file=self.create_uploaded_file(name="portfolio.txt"),
        )

        self.client.force_authenticate(user=user)

        response = self.client.get(f"/account/role-requests/{role_request.pk}/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            len(response.data["attachment_urls"]),
            1,
        )

        self.assertIn(
            "/media/role_requests/",
            response.data["attachment_urls"][0],
        )

    def test_user_can_cancel_pending_request_and_set_reviewed_at(self):
        user = self.create_active_user(username="cancel_with_timestamp")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "Teacher application.",
        )

        self.client.force_authenticate(user=user)

        before_cancel = timezone.now()

        response = self.client.post(f"/account/role-requests/{role_request.pk}/cancel/")

        after_cancel = timezone.now()

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        role_request.refresh_from_db()

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.CANCELLED,
        )

        self.assertIsNotNone(role_request.reviewed_at)

        self.assertGreaterEqual(
            role_request.reviewed_at,
            before_cancel,
        )

        self.assertLessEqual(
            role_request.reviewed_at,
            after_cancel,
        )

    def test_cancel_response_message(self):
        user = self.create_active_user(username="cancel_message")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(f"/account/role-requests/{role_request.pk}/cancel/")

        self.assertEqual(
            response.data["detail"],
            "Role request cancelled successfully.",
        )

    def test_user_cannot_cancel_approved_request(self):
        user = self.create_active_user(username="cancel_approved")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        role_request.status = RoleRequest.Status.APPROVED

        role_request.save(update_fields=["status"])

        self.client.force_authenticate(user=user)

        response = self.client.post(f"/account/role-requests/{role_request.pk}/cancel/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_user_cannot_cancel_rejected_request(self):
        user = self.create_active_user(username="cancel_rejected")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        role_request.status = RoleRequest.Status.REJECTED

        role_request.reviewed_at = timezone.now()

        role_request.save(
            update_fields=[
                "status",
                "reviewed_at",
            ]
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(f"/account/role-requests/{role_request.pk}/cancel/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_user_cannot_cancel_another_users_request(self):
        user = self.create_active_user(username="cancel_owner")

        other_user = self.create_active_user(
            username="cancel_target",
            email="cancel_target@example.com",
        )

        role_request = self.create_role_request(
            other_user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(f"/account/role-requests/{role_request.pk}/cancel/")

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_cancel_nonexistent_role_request_returns_404(self):
        user = self.create_active_user(username="cancel_missing")

        self.client.force_authenticate(user=user)

        response = self.client.post("/account/role-requests/999999/cancel/")

        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
        )

    # ==================================================================
    # ROLE REQUEST COOLDOWN TESTS
    # ==================================================================

    def test_rejected_role_has_seven_day_cooldown(self):
        user = self.create_active_user(username="cooldown_user")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "Rejected request.",
        )

        role_request.status = RoleRequest.Status.REJECTED

        role_request.reviewed_at = timezone.now()

        role_request.save(
            update_fields=[
                "status",
                "reviewed_at",
            ]
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Try again.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_rejected_role_can_be_requested_after_seven_days(self):
        user = self.create_active_user(
            username="rejected_after_week",
        )

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        role_request.status = RoleRequest.Status.REJECTED
        role_request.created_at = timezone.now() - timedelta(days=8)
        role_request.reviewed_at = timezone.now() - timedelta(days=8)

        role_request.save(
            update_fields=[
                "status",
                "created_at",
                "reviewed_at",
            ]
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "New teacher request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

    def test_teacher_cooldown_does_not_block_author_request(self):
        user = self.create_active_user(username="independent_cooldown")

        teacher_request = self.create_role_request(
            user,
            self.teacher_role,
            "Rejected teacher request.",
        )

        teacher_request.status = RoleRequest.Status.REJECTED

        teacher_request.reviewed_at = timezone.now()

        teacher_request.save(
            update_fields=[
                "status",
                "reviewed_at",
            ]
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Author",
                "description": "Author request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

    # ==================================================================
    # ADMIN ROLE REQUEST TESTS
    # ==================================================================

    def test_normal_user_cannot_list_admin_role_requests(self):
        user = self.create_active_user(username="normal_admin_list")

        self.client.force_authenticate(user=user)

        response = self.client.get("/account/admin/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_admin_can_list_role_requests(self):
        admin = self.create_admin()

        self.client.force_authenticate(user=admin)

        response = self.client.get("/account/admin/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

    def test_unauthenticated_user_cannot_list_admin_role_requests(
        self,
    ):
        response = self.client.get("/account/admin/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_admin_can_filter_role_requests_by_status(self):
        admin = self.create_admin()
        user = self.create_active_user(username="filter_user")

        pending_request = self.create_role_request(
            user,
            self.teacher_role,
            "Pending request.",
        )

        rejected_request = self.create_role_request(
            user,
            self.author_role,
            "Rejected request.",
        )

        rejected_request.status = RoleRequest.Status.REJECTED

        rejected_request.reviewed_at = timezone.now()
        rejected_request.reviewer = admin

        rejected_request.save(
            update_fields=[
                "status",
                "reviewed_at",
                "reviewer",
            ]
        )

        self.client.force_authenticate(user=admin)

        response = self.client.get("/account/admin/role-requests/?status=Pending")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            len(response.data),
            1,
        )

        self.assertEqual(
            response.data[0]["id"],
            pending_request.id,
        )

    def test_admin_filter_returns_empty_for_unused_status(self):
        admin = self.create_admin()

        self.client.force_authenticate(user=admin)

        response = self.client.get("/account/admin/role-requests/?status=Approved")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            len(response.data),
            0,
        )

    def test_admin_can_view_role_request_detail(self):
        admin = self.create_admin()
        user = self.create_active_user(username="admin_detail_user")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "Teacher application.",
        )

        self.client.force_authenticate(user=admin)

        response = self.client.get(f"/account/admin/role-requests/{role_request.pk}/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            response.data["id"],
            role_request.id,
        )

    def test_normal_user_cannot_view_admin_role_request_detail(
        self,
    ):
        user = self.create_active_user(username="admin_detail_normal")

        target_user = self.create_active_user(
            username="admin_detail_target",
            email="admin_detail_target@example.com",
        )

        role_request = self.create_role_request(
            target_user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=user)

        response = self.client.get(f"/account/admin/role-requests/{role_request.pk}/")

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_admin_can_approve_teacher_request(self):
        admin = self.create_admin()
        user = self.create_active_user(username="approve_teacher")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "Teacher application.",
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {
                "status": "Approved",
                "review_note": "Approved.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        role_request.refresh_from_db()

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.APPROVED,
        )

        self.assertEqual(
            role_request.reviewer,
            admin,
        )

        self.assertIsNotNone(role_request.reviewed_at)

        self.assertEqual(
            role_request.review_note,
            "Approved.",
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.teacher_role,
            ).exists()
        )

    def test_admin_can_approve_author_request(self):
        admin = self.create_admin()
        user = self.create_active_user(username="approve_author")

        role_request = self.create_role_request(
            user,
            self.author_role,
            "Author application.",
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {
                "status": "Approved",
                "review_note": "Approved author.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        role_request.refresh_from_db()

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.APPROVED,
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.author_role,
            ).exists()
        )

    def test_admin_can_reject_request(self):
        admin = self.create_admin()
        user = self.create_active_user(username="reject_request")

        role_request = self.create_role_request(
            user,
            self.author_role,
            "Author application.",
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {
                "status": "Rejected",
                "review_note": "Rejected.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        role_request.refresh_from_db()

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.REJECTED,
        )

        self.assertEqual(
            role_request.reviewer,
            admin,
        )

        self.assertIsNotNone(role_request.reviewed_at)

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.author_role,
            ).exists()
        )

    def test_admin_can_review_without_review_note(self):
        admin = self.create_admin()
        user = self.create_active_user(username="approve_no_note")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {"status": "Approved"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        role_request.refresh_from_db()

        self.assertEqual(
            role_request.review_note,
            "",
        )

    def test_admin_cannot_review_already_processed_request(self):
        admin = self.create_admin()
        user = self.create_active_user(username="processed_request")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        role_request.status = RoleRequest.Status.REJECTED

        role_request.reviewed_at = timezone.now()
        role_request.reviewer = admin

        role_request.save(
            update_fields=[
                "status",
                "reviewed_at",
                "reviewer",
            ]
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {"status": "Approved"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_admin_cannot_cancel_request_using_review_endpoint(self):
        admin = self.create_admin()
        user = self.create_active_user(username="admin_cancel_attempt")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {"status": "Cancelled"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_admin_review_requires_status(self):
        admin = self.create_admin()
        user = self.create_active_user(username="review_no_status")

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_normal_user_cannot_review_role_request(self):
        user = self.create_active_user(username="not_admin_review")

        target_user = self.create_active_user(
            username="review_target",
            email="review_target@example.com",
        )

        role_request = self.create_role_request(
            target_user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=user)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {"status": "Approved"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        role_request.refresh_from_db()

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.PENDING,
        )

    def test_admin_approval_does_not_create_duplicate_user_role(
        self,
    ):
        admin = self.create_admin()
        user = self.create_active_user(username="duplicate_approval")

        UserRole.objects.get_or_create(
            user=user,
            role=self.teacher_role,
        )

        role_request = self.create_role_request(
            user,
            self.teacher_role,
        )

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{role_request.pk}/review/",
            {"status": "Approved"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertEqual(
            UserRole.objects.filter(
                user=user,
                role=self.teacher_role,
            ).count(),
            1,
        )

    # ==================================================================
    # GOOGLE AUTHENTICATION TESTS
    # ==================================================================

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_signup_creates_member(
        self,
        mock_verify,
    ):
        mock_verify.return_value = self.google_payload(
            google_id="google-new-member",
            email="newgoogle@example.com",
            given_name="Google",
            family_name="New",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertIn(
            "access",
            response.data,
        )

        self.assertIn(
            "refresh",
            response.data,
        )

        self.assertTrue(response.data["is_new_user"])

        user = UserBase.objects.get(google_id="google-new-member")

        self.assertEqual(
            user.Email,
            "newgoogle@example.com",
        )

        self.assertEqual(
            user.FName,
            "Google New",
        )

        self.assertTrue(user.is_active)

        self.assertFalse(user.has_usable_password())

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.member_role,
            ).exists()
        )

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.teacher_role,
            ).exists()
        )

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.author_role,
            ).exists()
        )

        mock_verify.assert_called_once_with(
            "fake-google-token",
            ANY,
            settings.GOOGLE_CLIENT_ID,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_existing_user_can_login(
        self,
        mock_verify,
    ):
        user = self.create_active_user(
            username="google_existing",
            email="existing@example.com",
            first_name="Old Name",
        )

        user.google_id = "existing-google-id"

        user.save(update_fields=["google_id"])

        mock_verify.return_value = self.google_payload(
            google_id="existing-google-id",
            email="existing@example.com",
            given_name="Updated",
            family_name="Name",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertFalse(response.data["is_new_user"])

        self.assertIn(
            "access",
            response.data,
        )

        self.assertIn(
            "refresh",
            response.data,
        )

        user.refresh_from_db()

        self.assertEqual(
            user.FName,
            "Updated Name",
        )

        self.assertEqual(
            UserBase.objects.filter(google_id="existing-google-id").count(),
            1,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_existing_email_without_google_link_is_rejected(
        self,
        mock_verify,
    ):
        self.create_active_user(
            username="email_conflict",
            email="google_conflict@example.com",
        )

        mock_verify.return_value = self.google_payload(
            google_id="new-google-id",
            email="google_conflict@example.com",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_409_CONFLICT,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_email_conflict_is_case_insensitive(
        self,
        mock_verify,
    ):
        self.create_active_user(
            username="case_email_user",
            email="google_case@example.com",
        )

        mock_verify.return_value = self.google_payload(
            google_id="case-google-id",
            email="GOOGLE_CASE@EXAMPLE.COM",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_409_CONFLICT,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_generates_unique_username(
        self,
        mock_verify,
    ):
        self.create_active_user(
            username="unique",
            email="unique@example.com",
        )

        mock_verify.return_value = self.google_payload(
            google_id="unique-google-id",
            email="unique@example.org",
            given_name="Google",
            family_name="User",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        user = UserBase.objects.get(google_id="unique-google-id")

        self.assertEqual(
            user.UserName,
            "unique1",
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_generates_second_unique_username_when_needed(
        self,
        mock_verify,
    ):
        self.create_active_user(
            username="john",
            email="john@example.com",
        )

        self.create_active_user(
            username="john1",
            email="john1@example.com",
        )

        mock_verify.return_value = self.google_payload(
            google_id="john-google-id",
            email="john@example.org",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        user = UserBase.objects.get(google_id="john-google-id")

        self.assertEqual(
            user.UserName,
            "john2",
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_missing_name_uses_email_prefix(
        self,
        mock_verify,
    ):
        mock_verify.return_value = {
            "sub": "missing-name-google",
            "email": "missingname@example.com",
            "email_verified": True,
            "given_name": "",
            "family_name": "",
        }

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        user = UserBase.objects.get(google_id="missing-name-google")

        self.assertEqual(
            user.FName,
            "missingname",
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_missing_given_name_but_has_family_name(
        self,
        mock_verify,
    ):
        mock_verify.return_value = self.google_payload(
            google_id="family-only-google",
            email="familyonly@example.com",
            given_name="",
            family_name="User",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        user = UserBase.objects.get(google_id="family-only-google")

        self.assertEqual(
            user.FName,
            "User",
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_missing_family_name_but_has_given_name(
        self,
        mock_verify,
    ):
        mock_verify.return_value = self.google_payload(
            google_id="given-only-google",
            email="givenonly@example.com",
            given_name="Google",
            family_name="",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        user = UserBase.objects.get(google_id="given-only-google")

        self.assertEqual(
            user.FName,
            "Google",
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_requires_id_token(
        self,
        mock_verify,
    ):
        response = self.client.post(
            "/account/login/google/",
            {},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        mock_verify.assert_not_called()

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_invalid_token_fails(
        self,
        mock_verify,
    ):
        mock_verify.side_effect = ValueError()

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "invalid-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertIn(
            "error",
            response.data,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_requires_sub_claim(
        self,
        mock_verify,
    ):
        mock_verify.return_value = {
            "email": "missing-sub@example.com",
            "email_verified": True,
            "given_name": "Missing",
            "family_name": "Sub",
        }

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_requires_email_claim(
        self,
        mock_verify,
    ):
        mock_verify.return_value = {
            "sub": "missing-email",
            "email_verified": True,
            "given_name": "Missing",
            "family_name": "Email",
        }

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_requires_verified_email(
        self,
        mock_verify,
    ):
        mock_verify.return_value = self.google_payload(email_verified=False)

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_missing_email_verified_claim_is_rejected(
        self,
        mock_verify,
    ):
        payload = self.google_payload()

        payload.pop("email_verified")

        mock_verify.return_value = payload

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_existing_user_keeps_same_google_account(
        self,
        mock_verify,
    ):
        user = self.create_active_user(
            username="same_google_user",
            email="same_google@example.com",
        )

        user.google_id = "same-google-id"

        user.save(update_fields=["google_id"])

        mock_verify.return_value = self.google_payload(
            google_id="same-google-id",
            email="same_google@example.com",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertFalse(response.data["is_new_user"])

        self.assertEqual(
            UserBase.objects.filter(google_id="same-google-id").count(),
            1,
        )

        self.assertEqual(
            UserBase.objects.filter(Email="same_google@example.com").count(),
            1,
        )

    # ==================================================================
    # PERMISSION TESTS
    # ==================================================================

    def test_is_role_teacher_allows_teacher(self):
        user = self.create_active_user(username="teacher_permission")

        UserRole.objects.get_or_create(
            user=user,
            role=self.teacher_role,
        )

        request = self.request_factory.get("/")

        request.user = user

        permission = IsRole("Teacher")()

        self.assertTrue(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_role_author_allows_author(self):
        user = self.create_active_user(username="author_permission")

        UserRole.objects.get_or_create(
            user=user,
            role=self.author_role,
        )

        request = self.request_factory.get("/")

        request.user = user

        permission = IsRole("Author")()

        self.assertTrue(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_role_teacher_denies_member(self):
        user = self.create_active_user(username="member_permission")

        request = self.request_factory.get("/")

        request.user = user

        permission = IsRole("Teacher")()

        self.assertFalse(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_role_denies_anonymous_user(self):
        request = self.request_factory.get("/")

        request.user = AnonymousUser()

        permission = IsRole("Teacher")()

        self.assertFalse(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_any_role_allows_teacher(self):
        user = self.create_active_user(username="any_teacher")

        UserRole.objects.get_or_create(
            user=user,
            role=self.teacher_role,
        )

        request = self.request_factory.get("/")

        request.user = user

        permission = IsAnyRole(
            "Teacher",
            "Author",
        )()

        self.assertTrue(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_any_role_allows_author(self):
        user = self.create_active_user(username="any_author")

        UserRole.objects.get_or_create(
            user=user,
            role=self.author_role,
        )

        request = self.request_factory.get("/")

        request.user = user

        permission = IsAnyRole(
            "Teacher",
            "Author",
        )()

        self.assertTrue(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_any_role_denies_member(self):
        user = self.create_active_user(username="any_member")

        request = self.request_factory.get("/")

        request.user = user

        permission = IsAnyRole(
            "Teacher",
            "Author",
        )()

        self.assertFalse(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_any_role_denies_anonymous_user(self):
        request = self.request_factory.get("/")

        request.user = AnonymousUser()

        permission = IsAnyRole(
            "Teacher",
            "Author",
        )()

        self.assertFalse(
            permission.has_permission(
                request,
                None,
            )
        )

    def test_is_role_name_is_generated(self):
        permission = IsRole("Teacher")

        self.assertEqual(
            permission.__name__,
            "IsRole_Teacher",
        )

    def test_is_any_role_name_is_generated(self):
        permission = IsAnyRole(
            "Teacher",
            "Author",
        )

        self.assertEqual(
            permission.__name__,
            "IsAnyRole_Teacher_Author",
        )

    def test_role_permission_mixin_converts_role_name(self):
        class TestView(
            RolePermissionMixin,
            APIView,
        ):
            permission_classes = ["Teacher"]

            def get(self, request):
                return Response({"ok": True})

        view = TestView()

        permissions = view.get_permissions()

        self.assertEqual(
            len(permissions),
            1,
        )

        self.assertEqual(
            permissions[0].__class__.__name__,
            "IsRole_Teacher",
        )

    def test_role_permission_mixin_supports_multiple_required_roles(
        self,
    ):
        class TestView(
            RolePermissionMixin,
            APIView,
        ):
            permission_classes = [
                "Teacher",
                "Author",
            ]

        view = TestView()

        permissions = view.get_permissions()

        self.assertEqual(
            len(permissions),
            2,
        )

        self.assertEqual(
            permissions[0].__class__.__name__,
            "IsRole_Teacher",
        )

        self.assertEqual(
            permissions[1].__class__.__name__,
            "IsRole_Author",
        )

    def test_role_permission_mixin_keeps_permission_classes(
        self,
    ):
        from rest_framework.permissions import IsAuthenticated

        class TestView(
            RolePermissionMixin,
            APIView,
        ):
            permission_classes = [
                IsAuthenticated,
                "Teacher",
            ]

        view = TestView()

        permissions = view.get_permissions()

        self.assertEqual(
            len(permissions),
            2,
        )

        self.assertIsInstance(
            permissions[0],
            IsAuthenticated,
        )

        self.assertEqual(
            permissions[1].__class__.__name__,
            "IsRole_Teacher",
        )

    def test_signup_rejects_password_shorter_than_eight_characters(self):
        data = self.signup_data()

        data["password"] = "1234567"

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertIn(
            "password",
            response.data,
        )

    def test_signup_accepts_password_with_eight_characters(self):
        data = self.signup_data()

        data["password"] = "12345678"

        response = self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

    def test_cancelled_request_blocks_new_request_for_seven_days(self):
        user = self.create_active_user(
            username="cancel_weekly",
        )

        self.create_role_request(
            user,
            self.teacher_role,
            "First teacher request.",
        )

        self.client.force_authenticate(user=user)

        cancel_response = self.client.post(
            f"/account/role-requests/"
            f"{RoleRequest.objects.get(user=user).pk}/cancel/"
        )

        self.assertEqual(
            cancel_response.status_code,
            status.HTTP_200_OK,
        )

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Second teacher request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_cancelled_request_allows_new_request_after_seven_days(self):
        user = self.create_active_user(
            username="cancel_after_week",
        )

        role_request = self.create_role_request(
            user,
            self.teacher_role,
            "Old teacher request.",
        )

        role_request.created_at = timezone.now() - timedelta(days=8)
        role_request.status = RoleRequest.Status.CANCELLED

        role_request.save(
            update_fields=[
                "created_at",
                "status",
            ]
        )

        self.client.force_authenticate(user=user)

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "New teacher request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
        )

    def test_user_can_remove_teacher_role(self):
        user = self.create_active_user(
            username="remove_teacher",
        )

        UserRole.objects.create(
            user=user,
            role=self.teacher_role,
        )

        self.client.force_authenticate(user=user)

        response = self.client.delete("/account/roles/Teacher/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.teacher_role,
            ).exists()
        )

    def test_user_cannot_remove_member_role(self):
        user = self.create_active_user(
            username="remove_member",
        )

        self.client.force_authenticate(user=user)

        response = self.client.delete("/account/roles/Member/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.member_role,
            ).exists()
        )

    def test_user_cannot_remove_admin_role(self):
        admin = self.create_admin()

        self.client.force_authenticate(user=admin)

        response = self.client.delete("/account/roles/Admin/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=admin,
                role=self.admin_role,
            ).exists()
        )

    @patch("Authentication.views.id_token.verify_oauth2_token")
    def test_google_rejects_inactive_existing_user(
        self,
        mock_verify,
    ):
        user = self.create_active_user(
            username="inactive_google_user",
            email="inactive_google@example.com",
        )

        user.google_id = "inactive-google-id"
        user.is_active = False

        user.save(
            update_fields=[
                "google_id",
                "is_active",
            ]
        )

        mock_verify.return_value = self.google_payload(
            google_id="inactive-google-id",
            email="inactive_google@example.com",
        )

        response = self.client.post(
            "/account/login/google/",
            {"id_token": "fake-google-token"},
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

        mock_verify.assert_called_once()
