from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import *

UserBase = get_user_model()


class MultipleFileField(serializers.ListField):
    """
    Allows multiple files to be uploaded using the same
    multipart/form-data field name.

    Example from React/FormData:

        formData.append("teacher_attachments", file1)
        formData.append("teacher_attachments", file2)
    """

    child = serializers.FileField()

    def get_value(self, dictionary):

        if hasattr(dictionary, "getlist"):
            return dictionary.getlist(self.field_name)

        return super().get_value(dictionary)


class UserBaseSerializer(serializers.ModelSerializer):

    ROLE_REQUEST_CHOICES = [
        ("None", "None"),
        ("Teacher", "Teacher"),
        ("Author", "Author"),
        ("Both", "Both"),
    ]

    role_request = serializers.ChoiceField(
        choices=ROLE_REQUEST_CHOICES, required=False, default="None", write_only=True
    )

    teacher_description = serializers.CharField(
        required=False, allow_blank=False, write_only=True
    )

    teacher_attachments = MultipleFileField(required=False, write_only=True)

    author_description = serializers.CharField(
        required=False, allow_blank=False, write_only=True
    )

    author_attachments = MultipleFileField(required=False, write_only=True)

    class Meta:

        model = UserBase

        fields = [
            "UserName",
            "FName",
            "Email",
            "password",
            "role_request",
            "teacher_description",
            "teacher_attachments",
            "author_description",
            "author_attachments",
        ]

        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):

        requested_type = attrs.get("role_request", "None")

        teacher_description = attrs.get("teacher_description")

        teacher_attachments = attrs.get("teacher_attachments", [])

        author_description = attrs.get("author_description")

        author_attachments = attrs.get("author_attachments", [])

        if requested_type == "None":

            if teacher_description:
                raise serializers.ValidationError(
                    {
                        "teacher_description": "Teacher description is not allowed when no "
                        "role is requested."
                    }
                )

            if teacher_attachments:
                raise serializers.ValidationError(
                    {
                        "teacher_attachments": "Teacher attachments are not allowed when no "
                        "role is requested."
                    }
                )

            if author_description:
                raise serializers.ValidationError(
                    {
                        "author_description": "Author description is not allowed when no "
                        "role is requested."
                    }
                )

            if author_attachments:
                raise serializers.ValidationError(
                    {
                        "author_attachments": "Author attachments are not allowed when no "
                        "role is requested."
                    }
                )

        elif requested_type == "Teacher":

            if not teacher_description:
                raise serializers.ValidationError(
                    {
                        "teacher_description": "A description is required when requesting "
                        "the Teacher role."
                    }
                )

            if author_description:
                raise serializers.ValidationError(
                    {
                        "author_description": "Author description is not allowed when only "
                        "the Teacher role is requested."
                    }
                )

            if author_attachments:
                raise serializers.ValidationError(
                    {
                        "author_attachments": "Author attachments are not allowed when only "
                        "the Teacher role is requested."
                    }
                )

        elif requested_type == "Author":

            if not author_description:
                raise serializers.ValidationError(
                    {
                        "author_description": "A description is required when requesting "
                        "the Author role."
                    }
                )

            if teacher_description:
                raise serializers.ValidationError(
                    {
                        "teacher_description": "Teacher description is not allowed when only "
                        "the Author role is requested."
                    }
                )

            if teacher_attachments:
                raise serializers.ValidationError(
                    {
                        "teacher_attachments": "Teacher attachments are not allowed when only "
                        "the Author role is requested."
                    }
                )

        elif requested_type == "Both":

            if not teacher_description:
                raise serializers.ValidationError(
                    {
                        "teacher_description": "A description is required for the Teacher "
                        "request."
                    }
                )

            if not author_description:
                raise serializers.ValidationError(
                    {
                        "author_description": "A description is required for the Author "
                        "request."
                    }
                )

        return attrs

    @transaction.atomic
    def create(self, validated_data):

        requested_type = validated_data.pop("role_request", "None")

        teacher_description = validated_data.pop("teacher_description", None)

        teacher_attachments = validated_data.pop("teacher_attachments", [])

        author_description = validated_data.pop("author_description", None)

        author_attachments = validated_data.pop("author_attachments", [])

        password = validated_data.pop("password")

        user = UserBase.objects.create_user(password=password, **validated_data)

        if requested_type == "None":
            return user

        if requested_type in ["Teacher", "Both"]:

            teacher_role = Role.objects.get(name="Teacher")

            teacher_request = RoleRequest.objects.create(
                user=user, requested_role=teacher_role, description=teacher_description
            )

            for uploaded_file in teacher_attachments:

                RoleRequestAttachment.objects.create(
                    request=teacher_request, file=uploaded_file
                )

        if requested_type in ["Author", "Both"]:

            author_role = Role.objects.get(name="Author")

            author_request = RoleRequest.objects.create(
                user=user, requested_role=author_role, description=author_description
            )

            for uploaded_file in author_attachments:

                RoleRequestAttachment.objects.create(
                    request=author_request, file=uploaded_file
                )

        return user


class RoleRequestSerializer(serializers.ModelSerializer):

    requested_role = serializers.SlugRelatedField(
        slug_field="name", queryset=Role.objects.filter(name__in=["Teacher", "Author"])
    )

    attachments = MultipleFileField(required=False, write_only=True)

    attachment_urls = serializers.SerializerMethodField(read_only=True)

    class Meta:

        model = RoleRequest

        fields = [
            "id",
            "requested_role",
            "description",
            "status",
            "review_note",
            "created_at",
            "reviewed_at",
            "attachments",
            "attachment_urls",
        ]

        read_only_fields = [
            "id",
            "status",
            "review_note",
            "created_at",
            "reviewed_at",
            "attachment_urls",
        ]

    def validate(self, attrs):

        user = self.context["request"].user

        requested_role = attrs.get("requested_role")

        role_name = requested_role.name

        if UserRole.objects.filter(user=user, role=requested_role).exists():

            raise serializers.ValidationError(
                {"requested_role": f"You already have the {role_name} role."}
            )

        pending_exists = RoleRequest.objects.filter(
            user=user, requested_role=requested_role, status=RoleRequest.Status.PENDING
        ).exists()

        if pending_exists:

            raise serializers.ValidationError(
                {
                    "requested_role": f"You already have a pending {role_name} "
                    "role request."
                }
            )

        last_rejected_request = (
            RoleRequest.objects.filter(
                user=user,
                requested_role=requested_role,
                status=RoleRequest.Status.REJECTED,
            )
            .order_by("-reviewed_at")
            .first()
        )

        if last_rejected_request and last_rejected_request.reviewed_at:

            cooldown_end = last_rejected_request.reviewed_at + timedelta(days=7)

            if timezone.now() < cooldown_end:

                remaining = cooldown_end - timezone.now()

                days = remaining.days
                hours = remaining.seconds // 3600

                raise serializers.ValidationError(
                    {
                        "requested_role": f"You must wait before requesting the "
                        f"{role_name} role again. "
                        f"Approximately {days} day(s) and "
                        f"{hours} hour(s) remaining."
                    }
                )

        return attrs

    @transaction.atomic
    def create(self, validated_data):

        attachments = validated_data.pop("attachments", [])

        user = self.context["request"].user

        role_request = RoleRequest.objects.create(user=user, **validated_data)

        for uploaded_file in attachments:

            RoleRequestAttachment.objects.create(
                request=role_request, file=uploaded_file
            )

        return role_request

    @transaction.atomic
    def update(self, instance, validated_data):

        user = self.context["request"].user

        if instance.user != user:

            raise serializers.ValidationError(
                "You can only modify your own role requests."
            )

        if instance.status != RoleRequest.Status.PENDING:

            raise serializers.ValidationError(
                "Only pending role requests can be cancelled."
            )

        instance.status = RoleRequest.Status.CANCELLED
        instance.reviewed_at = timezone.now()
        instance.save(update_fields=["status", "reviewed_at"])

        return instance

    def get_attachment_urls(self, obj):

        request = self.context.get("request")

        urls = []

        for attachment in obj.attachments.all():

            if request:

                urls.append(request.build_absolute_uri(attachment.file.url))

            else:

                urls.append(attachment.file.url)

        return urls


class AdminRoleRequestSerializer(serializers.ModelSerializer):

    attachment_urls = serializers.SerializerMethodField(read_only=True)

    class Meta:

        model = RoleRequest

        fields = [
            "id",
            "user",
            "requested_role",
            "description",
            "status",
            "reviewer",
            "review_note",
            "created_at",
            "reviewed_at",
            "attachment_urls",
        ]

        read_only_fields = [
            "id",
            "user",
            "requested_role",
            "description",
            "reviewer",
            "created_at",
            "reviewed_at",
            "attachment_urls",
        ]

    @transaction.atomic
    def update(self, instance, validated_data):

        admin_user = self.context["request"].user

        new_status = validated_data.get("status")

        review_note = validated_data.get("review_note", instance.review_note)

        if instance.status != RoleRequest.Status.PENDING:

            raise serializers.ValidationError(
                "Only pending role requests can be reviewed."
            )

        if new_status not in [RoleRequest.Status.APPROVED, RoleRequest.Status.REJECTED]:

            raise serializers.ValidationError(
                {"status": "Admin can only approve or reject a request."}
            )

        instance.status = new_status
        instance.review_note = review_note
        instance.reviewer = admin_user
        instance.reviewed_at = timezone.now()

        if new_status == RoleRequest.Status.APPROVED:

            UserRole.objects.get_or_create(
                user=instance.user, role=instance.requested_role
            )

        instance.save()

        return instance

    def get_attachment_urls(self, obj):

        request = self.context.get("request")

        urls = []

        for attachment in obj.attachments.all():

            if request:

                urls.append(request.build_absolute_uri(attachment.file.url))

            else:

                urls.append(attachment.file.url)

        return urls


class UserTokenObtainSerializer(TokenObtainPairSerializer):
    username_field = "UserName"
