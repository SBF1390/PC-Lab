from uuid import uuid4

from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import TestCase, override_settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APIClient

from .models import Role, RoleRequest, UserBase, UserRole


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"],
)
class AuthenticationTests(TestCase):

    PASSWORD = "TestPassword123!Secure"

    def setUp(self):
        self.client = APIClient()

        self.member_role = Role.objects.get_or_create(name="Member")[0]
        self.teacher_role = Role.objects.get_or_create(name="Teacher")[0]
        self.author_role = Role.objects.get_or_create(name="Author")[0]
        self.admin_role = Role.objects.get_or_create(name="Admin")[0]

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
            "FName": "Test",
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

    def create_admin(self):
        return UserBase.objects.create_superuser(
            UserName=f"admin_{uuid4().hex[:8]}",
            password=self.PASSWORD,
            FName="Admin",
            Email=f"{uuid4().hex[:8]}@example.com",
        )

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

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [data["Email"]])
        self.assertIn(
            "Activate your PC-Lab account",
            mail.outbox[0].subject,
        )
        self.assertIn(
            "/account/activate/",
            mail.outbox[0].body,
        )

    def test_teacher_signup_creates_teacher_request(self):
        data = self.signup_data(
            role_request="Teacher",
            teacher_description="I want to become a teacher.",
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

        request = RoleRequest.objects.get(
            user=user,
            requested_role=self.teacher_role,
        )

        self.assertEqual(
            request.status,
            RoleRequest.Status.PENDING,
        )

        self.assertEqual(
            request.description,
            data["teacher_description"],
        )

    def test_author_signup_creates_author_request(self):
        data = self.signup_data(
            role_request="Author",
            author_description="I want to become an author.",
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

        request = RoleRequest.objects.get(
            user=user,
            requested_role=self.author_role,
        )

        self.assertEqual(
            request.status,
            RoleRequest.Status.PENDING,
        )

        self.assertEqual(
            request.description,
            data["author_description"],
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

        self.assertTrue(
            RoleRequest.objects.filter(
                user=user,
                requested_role=self.teacher_role,
                status=RoleRequest.Status.PENDING,
            ).exists()
        )

        self.assertTrue(
            RoleRequest.objects.filter(
                user=user,
                requested_role=self.author_role,
                status=RoleRequest.Status.PENDING,
            ).exists()
        )

    def test_teacher_request_requires_description(self):
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

    def test_author_request_requires_description(self):
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

    def test_invalid_activation_token_fails(self):
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

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

        response = self.client.get(f"/account/activate/{uidb64}/invalid-token/")

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

        user.refresh_from_db()

        self.assertFalse(user.is_active)

    def test_inactive_user_cannot_login(self):
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

        login_response = self.login_user(data["UserName"])

        self.assertEqual(
            login_response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_active_user_can_login(self):
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

        activation_response = self.activate_user(user)

        self.assertEqual(
            activation_response.status_code,
            status.HTTP_200_OK,
        )

        login_response = self.login_user(data["UserName"])

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        self.assertIn(
            "access",
            login_response.data,
        )

        self.assertIn(
            "refresh",
            login_response.data,
        )

    def test_wrong_password_fails(self):
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

        self.activate_user(user)

        response = self.login_user(
            data["UserName"],
            "WrongPassword123!",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_refresh_token_works(self):
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

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

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

    def test_authenticated_user_can_create_role_request(self):
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

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

        self.authenticate(login_response.data["access"])

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

    def test_unauthenticated_user_cannot_access_role_requests(self):
        response = self.client.get("/account/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
        )

    def test_user_can_list_own_role_requests(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

        self.authenticate(login_response.data["access"])

        self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Author",
                "description": "Author request.",
            },
            format="json",
        )

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
            response.data[0]["requested_role"],
            "Author",
        )

    def test_user_can_cancel_pending_request(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

        self.authenticate(login_response.data["access"])

        create_response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Teacher request.",
            },
            format="json",
        )

        request_id = create_response.data["id"]

        response = self.client.post(f"/account/role-requests/{request_id}/cancel/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

        role_request = RoleRequest.objects.get(pk=request_id)

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.CANCELLED,
        )

    def test_admin_can_list_role_requests(self):
        admin = self.create_admin()

        self.client.force_authenticate(user=admin)

        response = self.client.get("/account/admin/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
        )

    def test_normal_user_cannot_access_admin_role_requests(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        self.client.force_authenticate(user=user)

        response = self.client.get("/account/admin/role-requests/")

        self.assertEqual(
            response.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_admin_can_approve_role_request(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

        self.authenticate(login_response.data["access"])

        create_response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Teacher request.",
            },
            format="json",
        )

        self.assertEqual(
            create_response.status_code,
            status.HTTP_201_CREATED,
        )

        request_id = create_response.data["id"]

        admin = self.create_admin()

        self.client.force_authenticate(user=admin)

        response = self.client.patch(
            f"/account/admin/role-requests/{request_id}/review/",
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

        role_request = RoleRequest.objects.get(pk=request_id)

        self.assertEqual(
            role_request.status,
            RoleRequest.Status.APPROVED,
        )

        self.assertEqual(
            role_request.reviewer,
            admin,
        )

        self.assertTrue(
            UserRole.objects.filter(
                user=user,
                role=self.teacher_role,
            ).exists()
        )

    def test_admin_can_reject_role_request(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        role_request = RoleRequest.objects.create(
            user=user,
            requested_role=self.author_role,
            description="Author request.",
        )

        admin = self.create_admin()

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

        self.assertFalse(
            UserRole.objects.filter(
                user=user,
                role=self.author_role,
            ).exists()
        )

    def test_duplicate_pending_role_request_is_rejected(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

        self.authenticate(login_response.data["access"])

        first_response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "First request.",
            },
            format="json",
        )

        self.assertEqual(
            first_response.status_code,
            status.HTTP_201_CREATED,
        )

        second_response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Second request.",
            },
            format="json",
        )

        self.assertEqual(
            second_response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_existing_role_cannot_be_requested(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        UserRole.objects.get_or_create(
            user=user,
            role=self.teacher_role,
        )

        login_response = self.login_user(data["UserName"])

        self.authenticate(login_response.data["access"])

        response = self.client.post(
            "/account/role-requests/",
            {
                "requested_role": "Teacher",
                "description": "Existing role request.",
            },
            format="json",
        )

        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_logout_blacklists_refresh_token(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

        self.assertEqual(
            login_response.status_code,
            status.HTTP_200_OK,
        )

        access_token = login_response.data["access"]
        refresh_token = login_response.data["refresh"]

        self.authenticate(access_token)

        logout_response = self.client.post(
            "/account/logout/",
            {"refresh": refresh_token},
            format="json",
        )

        self.assertEqual(
            logout_response.status_code,
            status.HTTP_205_RESET_CONTENT,
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

    def test_logout_requires_refresh_token(self):
        data = self.signup_data()

        self.client.post(
            "/account/signup/",
            data,
            format="multipart",
        )

        user = UserBase.objects.get(UserName=data["UserName"])

        self.activate_user(user)

        login_response = self.login_user(data["UserName"])

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
