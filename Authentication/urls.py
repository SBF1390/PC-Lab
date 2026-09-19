from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import *

urlpatterns = [
    path("signup/", SignUpView.as_view()),
    path("login/", LoginView.as_view()),
    path("logout/", LogOutView.as_view()),
    path("token/refresh/", TokenRefreshView.as_view()),
    path("activate/<uidb64>/<token>/", ActivateAccountView.as_view()),
    path("role-requests/", UserRoleRequestListCreateView.as_view()),
    path("role-requests/<int:pk>/", UserRoleRequestDetailView.as_view()),
    path("role-requests/<int:pk>/cancel/", UserRoleRequestCancelView.as_view()),
    path("admin/role-requests/", AdminRoleRequestListView.as_view()),
    path("admin/role-requests/<int:pk>/", AdminRoleRequestDetailView.as_view()),
    path("admin/role-requests/<int:pk>/review/", AdminRoleRequestReviewView.as_view()),
]