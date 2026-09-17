from django.db import migrations


def create_default_roles(apps, schema_editor):
    Role = apps.get_model("Authentication", "Role")

    roles = [
        "Member",
        "Teacher",
        "Author",
        "Admin",
    ]

    for role_name in roles:
        Role.objects.get_or_create(name=role_name)


def reverse_default_roles(apps, schema_editor):
    Role = apps.get_model("Authentication", "Role")

    Role.objects.filter(
        name__in=[
            "Member",
            "Teacher",
            "Author",
            "Admin",
        ]
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("Authentication", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_default_roles, reverse_default_roles),
    ]
