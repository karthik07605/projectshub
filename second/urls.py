from django.contrib import admin
from django.urls import path, include
from .views import *

urlpatterns = [
    path("", home, name='home'),
    path("admin/", admin.site.urls),
    path("project/<int:project_id>/", project_detail, name='project_detail'),
    path("userprofile/", profile, name='userprofile'),
    path('send-otp/', send_otp, name='send_otp'),
    path('verify-otp/', verify_otp, name='verify_otp'),
    path('signup/', signup, name='signup'),
    path('get-csrf-token/', get_csrf_token, name='get_csrf_token'),
    path('upload-project/', upload_project, name='upload_project'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('login-security/', login_security, name='login_security'),
    path('update-profile/', update_profile, name='update_profile'),
    path('delete-account/', delete_account, name='delete_account'),
    path('uploaded-projects/', uploaded_projects, name='uploaded_projects'),
    path('accounts/', include('allauth.urls')),
    path('reset_password/', reset_password, name='password_reset_request'),
    path('reset_password_confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('toggle_like/', toggle_like, name='toggle_like'),
    path('clear-next-session/', clear_next_session, name='clear_next_session'),
    path('change-password/', change_password, name='change_password'),
    path('user-project/<int:project_id>/', user_project_detail, name='user_project_detail'),
    path('edit-project/', edit_project, name='edit_project'),
    path('delete-project/', delete_project, name='delete_project'),
    # Team member request URLs
    path('request-team-members/', request_team_members, name='request_team_members'),
    path('edit-team-request/<int:request_id>/', edit_team_request, name='edit_team_request'),
    path('delete-team-request/', delete_team_request, name='delete_team_request'),
    path('apply-team-request/', apply_team_request, name='apply_team_request'),
    path('team-request/<int:request_id>/', team_request_detail, name='team_request_detail'),
    path('team-requests/', team_requests, name='team_requests'),
    path('manage-team-application/', manage_team_application, name='manage_team_application'),
    path('application-status/', application_status, name='application_status'),
]