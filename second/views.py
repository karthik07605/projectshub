from django.core.mail import EmailMessage
from django.conf import settings
from email.utils import formataddr
from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import *
from .utils import send_otp_email
from django.middleware.csrf import get_token
from .cloudinary_utils import upload_to_cloudinary
import logging
import re
import cloudinary
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q

logger = logging.getLogger(__name__)

def get_csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})

def clear_next_session(request):
    if request.method == 'POST':
        if 'next' in request.session:
            del request.session['next']
        return JsonResponse({'status': 'Success'})
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

def send_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            logger.warning("Send OTP attempted with missing email")
            return JsonResponse({'status': 'Failed', 'message': 'Email is required'}, status=400)
        email_lower = email.lower()
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email_lower):
            logger.warning(f"Invalid email format: {email_lower}")
            return JsonResponse({'status': 'Failed', 'message': 'Invalid email format'}, status=400)
        try:
            if User.objects.filter(email__iexact=email_lower).exists():
                logger.info(f"Attempted to send OTP for already registered email {email_lower}")
                return JsonResponse({'status': 'Failed', 'message': 'Email already registered'}, status=400)
            EmailOTP.objects.filter(email__iexact=email_lower).delete()
            otp_instance = EmailOTP.objects.create(email=email_lower)
            otp_instance.generate_otp()
            try:
                send_otp_email({'email': email_lower}, otp_instance.otp)
                logger.info(f"OTP sent to {email_lower}")
                return JsonResponse({'status': 'OTP Sent', 'message': 'OTP sent to your email'})
            except Exception as e:
                logger.error(f"Failed to send OTP to {email_lower}: {str(e)}")
                return JsonResponse({'status': 'Failed', 'message': f'Failed to send OTP: {str(e)}'}, status=500)
        except Exception as e:
            logger.error(f"Error in send_otp for {email_lower}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': f'An unexpected error occurred: {str(e)}'}, status=500)
    logger.warning(f"Invalid method for /send-otp/: {request.method}")
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = request.POST.get('otp')
        if not email or not otp:
            logger.warning(f"Missing email or OTP: email={email}, otp={otp}")
            return JsonResponse({'status': 'Failed', 'message': 'Email and OTP are required'}, status=400)
        email_lower = email.lower()
        try:
            otp_instance = EmailOTP.objects.filter(email__iexact=email_lower).first()
            if not otp_instance:
                logger.error(f"OTP instance not found for email {email_lower}")
                return JsonResponse({'status': 'Error', 'message': 'OTP not found. Please request a new OTP.'}, status=400)
            if otp_instance.otp == otp:
                if (timezone.now() - otp_instance.created_at).seconds > 3600:
                    logger.warning(f"Expired OTP for {email_lower}")
                    return JsonResponse({'status': 'Failed', 'message': 'OTP has expired. Please request a new OTP.'}, status=400)
                logger.info(f"OTP verified for {email_lower}")
                return JsonResponse({'status': 'Verified'})
            else:
                logger.warning(f"Invalid OTP for {email_lower}: provided={otp}, expected={otp_instance.otp}")
                return JsonResponse({'status': 'Failed', 'message': 'Invalid OTP. Please try again.'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error during OTP verification for {email_lower}: {str(e)}")
            return JsonResponse({'status': 'Error', 'message': 'An unexpected error occurred'}, status=500)
    logger.warning(f"Invalid method for /verify-otp/: {request.method}")
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

def signup(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        if not all([name, email, mobile, password]):
            return JsonResponse({'status': 'Failed', 'message': 'All fields are required'}, status=400)
        email_lower = email.lower()
        try:
            otp_instance = EmailOTP.objects.filter(email__iexact=email_lower).first()
            if not otp_instance:
                return JsonResponse({'status': 'Failed', 'message': 'Please verify your email with OTP.'}, status=400)
            if (timezone.now() - otp_instance.created_at).seconds > 3600:
                otp_instance.delete()
                return JsonResponse({'status': 'Failed', 'message': 'OTP has expired. Please request a new OTP.'}, status=400)
            if User.objects.filter(email__iexact=email_lower).exists():
                return JsonResponse({'status': 'Failed', 'message': 'Email already registered. Please log in.'}, status=400)
            username = email_lower.split('@')[0]
            base_username = username
            counter = 1
            while User.objects.filter(username__iexact=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            user = User.objects.create_user(
                username=username,
                email=email_lower,
                password=password,
                is_active=True
            )
            Profile.objects.create(user=user, name=name, mobile=mobile)
            otp_instance.delete()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            logger.info(f"User {email_lower} registered and logged in")
            return JsonResponse({'status': 'Success', 'message': 'Registration successful', 'redirect': '/'})
        except Exception as e:
            logger.error(f"Signup error for {email_lower}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred during registration'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def request_team_members(request):
    if request.method == 'GET':
        return render(request, 'request_team_members.html')
    elif request.method == 'POST':
        project_name = request.POST.get('project_name')
        description = request.POST.get('description')
        team_size = request.POST.get('team_size')
        required_skills = request.POST.get('required_skills')
        if not all([project_name, description, team_size, required_skills]):
            logger.warning(f"Team member request failed for user {request.user.username}: Missing fields")
            return JsonResponse({'status': 'Failed', 'message': 'All fields are required'}, status=400)
        try:
            team_size = int(team_size)
            if team_size <= 0:
                return JsonResponse({'status': 'Failed', 'message': 'Team size must be a positive number'}, status=400)
        except ValueError:
            logger.warning(f"Invalid team size provided by {request.user.username}: {team_size}")
            return JsonResponse({'status': 'Failed', 'message': 'Invalid team size'}, status=400)
        try:
            team_request = TeamMemberRequest.objects.create(
                user=request.user,
                project_name=project_name,
                description=description,
                team_size=team_size,
                required_skills=required_skills
            )
            logger.info(f"Team member request '{project_name}' created by user {request.user.username}")
            return JsonResponse({
                'status': 'Success',
                'message': 'Team member request posted successfully',
                'redirect': '/userprofile/'
            })
        except Exception as e:
            logger.error(f"Error creating team request for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def edit_team_request(request, request_id):
    team_request = get_object_or_404(TeamMemberRequest, id=request_id)
    if team_request.user != request.user:
        logger.warning(f"User {request.user.username} attempted to edit team request {request_id} they do not own")
        return JsonResponse({'status': 'Failed', 'message': 'You do not have permission to edit this request'}, status=403)
    if request.method == 'GET':
        return render(request, 'request_team_members.html', {'team_request': team_request})
    elif request.method == 'POST':
        project_name = request.POST.get('project_name')
        description = request.POST.get('description')
        team_size = request.POST.get('team_size')
        required_skills = request.POST.get('required_skills')
        if not all([project_name, description, team_size, required_skills]):
            logger.warning(f"Edit team request failed for user {request.user.username}: Missing fields")
            return JsonResponse({'status': 'Failed', 'message': 'All fields are required'}, status=400)
        try:
            team_size = int(team_size)
            if team_size <= 0:
                return JsonResponse({'status': 'Failed', 'message': 'Team size must be a positive number'}, status=400)
        except ValueError:
            logger.warning(f"Invalid team size provided by {request.user.username}: {team_size}")
            return JsonResponse({'status': 'Failed', 'message': 'Invalid team size'}, status=400)
        try:
            team_request.project_name = project_name
            team_request.description = description
            team_request.team_size = team_size
            team_request.required_skills = required_skills
            team_request.save()
            logger.info(f"Team request '{project_name}' edited by user {request.user.username}")
            return JsonResponse({
                'status': 'Success',
                'message': 'Team member request updated successfully',
                'redirect': '/userprofile/'
            })
        except Exception as e:
            logger.error(f"Error editing team request {request_id} for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def delete_team_request(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            request_id = data.get('request_id')
            if not request_id:
                return JsonResponse({'status': 'Failed', 'message': 'Request ID is required'}, status=400)
            team_request = get_object_or_404(TeamMemberRequest, id=request_id)
            if team_request.user != request.user:
                logger.warning(f"User {request.user.username} attempted to delete team request {request_id} they do not own")
                return JsonResponse({'status': 'Failed', 'message': 'You do not have permission to delete this request'}, status=403)
            project_name = team_request.project_name
            team_request.delete()
            logger.info(f"Team request '{project_name}' deleted by user {request.user.username}")
            return JsonResponse({'status': 'Success', 'message': 'Team member request deleted successfully'})
        except Exception as e:
            logger.error(f"Error deleting team request for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def apply_team_request(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            request_id = data.get('request_id')
            message = data.get('message', '')
            if not request_id:
                return JsonResponse({'status': 'Failed', 'message': 'Request ID is required'}, status=400)
            team_request = get_object_or_404(TeamMemberRequest, id=request_id)
            if team_request.user == request.user:
                return JsonResponse({'status': 'Failed', 'message': 'You cannot apply to your own request'}, status=400)
            application, created = TeamMemberApplication.objects.get_or_create(
                user=request.user,
                team_request=team_request,
                defaults={'message': message}
            )
            if not created:
                logger.info(f"User {request.user.username} attempted to apply again to team request {team_request.project_name}")
                return JsonResponse({'status': 'Failed', 'message': 'You have already applied to this request'}, status=400)
            logger.info(f"User {request.user.username} applied to team request {team_request.project_name}")
            return JsonResponse({
                'status': 'Success',
                'message': 'Application submitted successfully'
            })
        except Exception as e:
            logger.error(f"Error applying to team request for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def team_request_detail(request, request_id):
    team_request = get_object_or_404(TeamMemberRequest, id=request_id)
    is_owner = team_request.user == request.user
    has_applied = TeamMemberApplication.objects.filter(user=request.user, team_request=team_request).exists()
    application_status = None
    if has_applied and not is_owner:
        application = TeamMemberApplication.objects.get(user=request.user, team_request=team_request)
        application_status = application.status
    applications = []
    if is_owner:
        applications = TeamMemberApplication.objects.filter(team_request=team_request).select_related('user__profile').order_by('-applied_at')
    return render(request, 'team_request_detail.html', {
        'team_request': team_request,
        'is_owner': is_owner,
        'has_applied': has_applied,
        'application_status': application_status,
        'applications': applications
    })

@login_required
def team_requests(request):
    team_requests = TeamMemberRequest.objects.filter(
        user=request.user
    ).select_related('user__profile').prefetch_related('applications__user__profile', 'applications__user__project_set').order_by('-created_at')
    return render(request, 'team_requests.html', {'team_requests': team_requests})

@login_required
def manage_team_application(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            application_id = data.get('application_id')
            action = data.get('action')
            if not application_id or not action:
                return JsonResponse({'status': 'Failed', 'message': 'Application ID and action are required'}, status=400)
            application = get_object_or_404(TeamMemberApplication, id=application_id)
            if application.team_request.user != request.user:
                logger.warning(f"User {request.user.username} attempted to manage application {application_id} they do not own")
                return JsonResponse({'status': 'Failed', 'message': 'You do not have permission to manage this application'}, status=403)
            if action not in ['accept', 'reject']:
                return JsonResponse({'status': 'Failed', 'message': 'Invalid action'}, status=400)
            application.status = 'Accepted' if action == 'accept' else 'Rejected'
            application.save()
            Notification.objects.create(
                user=application.user,
                team_request=application.team_request,
                status=application.status,
                read=False
            )
            logger.info(f"Application {application_id} {action}ed by user {request.user.username} for team request {application.team_request.project_name}")
            return JsonResponse({
                'status': 'Success',
                'message': f'Application {action}ed successfully'
            })
        except Exception as e:
            logger.error(f"Error managing application for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def application_status(request):
    applications = TeamMemberApplication.objects.filter(
        user=request.user
    ).select_related('team_request__user__profile').order_by('-applied_at')
    return render(request, 'application_status.html', {
        'applications': applications
    })

def home(request):
    projects = Project.objects.all().select_related('user__profile')
    team_requests = TeamMemberRequest.objects.all().select_related('user__profile')
    notifications = []
    if request.user.is_authenticated:
        notifications = Notification.objects.filter(
            user=request.user,
            read=False
        ).select_related('team_request').order_by('-created_at')
    combined_items = []
    for project in projects:
        combined_items.append({
            'id': project.id,
            'name': project.name,
            'type': project.type.lower() if project.type else 'other',
            'user': project.user,
            'created_at': project.created_at,
            'like_count': project.like_count,
            'image_urls': project.image_urls.split(',') if project.image_urls else [],
            'is_project': True
        })
    for team_request in team_requests:
        combined_items.append({
            'id': team_request.id,
            'name': team_request.project_name,
            'type': 'teamrequests',
            'user': team_request.user,
            'created_at': team_request.created_at,
            'like_count': 0,
            'image_urls': [],
            'is_project': False
        })
    combined_items.sort(key=lambda x: x['created_at'], reverse=True)
    liked_projects = []
    applied_requests = []
    if request.user.is_authenticated:
        liked_projects = Like.objects.filter(user=request.user).values_list('project_id', flat=True)
        applied_requests = TeamMemberApplication.objects.filter(user=request.user).values_list('team_request_id', flat=True)
    return render(request, 'home.html', {
        'items': combined_items,
        'liked_projects': liked_projects,
        'applied_requests': applied_requests,
        'notifications': notifications
    })

@login_required(login_url='/login/')
def project_detail(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    is_liked = Like.objects.filter(user=request.user, project=project).exists()
    return render(request, 'project_detail.html', {'project': project, 'is_liked': is_liked})

@login_required
def profile(request):
    profile, created = Profile.objects.get_or_create(user=request.user)
    if created:
        profile.name = request.user.username
        profile.mobile = ''
        profile.save()
        logger.info(f"Created profile for user {request.user.username}")
    team_requests = TeamMemberRequest.objects.filter(user=request.user).select_related('user__profile')
    return render(request, 'userprofile.html', {
        'profile': profile,
        'user': request.user,
        'team_requests': team_requests
    })

@login_required
def login_security(request):
    if request.method == 'GET':
        profile = request.user.profile
        return render(request, 'login-security.html', {'profile': profile, 'user': request.user})
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def update_profile(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        mobile = request.POST.get('mobile')
        if not name or not mobile:
            return JsonResponse({'status': 'Failed', 'message': 'Name and mobile are required'}, status=400)
        profile = request.user.profile
        profile.name = name
        profile.mobile = mobile
        profile.save()
        logger.info(f"Profile updated for user {request.user.username}")
        return JsonResponse({'status': 'Success'})
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        username = user.username
        user.delete()
        logger.info(f"Account deleted for user {username}")
        return JsonResponse({'status': 'Success', 'message': 'Account deleted successfully'})
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def uploaded_projects(request):
    user_projects = Project.objects.filter(user=request.user)
    return render(request, 'uploaded-projects.html', {'user_projects': user_projects})

@login_required
def upload_project(request):
    if request.method == 'GET':
        return render(request, 'upload-project.html')
    elif request.method == 'POST':
        if request.user.is_authenticated:
            name = request.POST.get('name')
            description = request.POST.get('description', '')
            project_type = request.POST.get('type', '')
            github_link = request.POST.get('github_link', '')
            if not name or not project_type:
                return JsonResponse({'status': 'Failed', 'message': 'Project name and type are required'}, status=400)
            if github_link and not re.match(r'^https:\/\/github\.com\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+$', github_link):
                logger.warning(f"Invalid GitHub link provided by {request.user.username}: {github_link}")
                return JsonResponse({'status': 'Failed', 'message': 'Invalid GitHub link format'}, status=400)
            max_size = 10 * 1024 * 1024
            if 'videos' in request.FILES:
                for video in request.FILES.getlist('videos'):
                    if video.size > max_size:
                        logger.warning(f"Video {video.name} exceeds 10MB for user {request.user.username}")
                        return JsonResponse({'status': 'Failed', 'message': f'Video {video.name} exceeds 10MB'}, status=400)
            project = Project.objects.create(
                user=request.user,
                name=name,
                type=project_type,
                description=description,
                github_link=github_link
            )
            if 'images' in request.FILES:
                images = request.FILES.getlist('images')
                image_urls = []
                for image in images:
                    try:
                        image_url = upload_to_cloudinary(image, image.name, resource_type='image')
                        image_urls.append(image_url)
                        logger.info(f"Uploaded image {image.name} to Cloudinary: {image_url}")
                    except Exception as e:
                        logger.error(f"Failed to upload image {image.name}: {e}")
                if image_urls:
                    project.image_urls = ','.join(image_urls)
            if 'videos' in request.FILES:
                videos = request.FILES.getlist('videos')
                video_urls = []
                for video in videos:
                    try:
                        video_url = upload_to_cloudinary(video, video.name, resource_type='video')
                        video_urls.append(video_url)
                        logger.info(f"Uploaded video {video.name} to Cloudinary: {video_url}")
                    except Exception as e:
                        logger.error(f"Failed to upload video {video.name}: {e}")
                if video_urls:
                    project.video_urls = ','.join(video_urls)
            project.save()
            logger.info(f"Project {name} uploaded by user {request.user.username}")
            return JsonResponse({'status': 'Success', 'message': 'Project uploaded successfully', 'project_id': project.id})
        return JsonResponse({'status': 'Failed', 'message': 'Authentication required'}, status=403)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

def login_view(request):
    if request.user.is_authenticated:
        logger.info(f"Authenticated user {request.user.username} redirected to home from login page")
        return redirect('home')
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        logger.debug(f"Login attempt for email: {email}")
        if not email or not password:
            logger.warning("Login attempted with missing email or password")
            return JsonResponse({'status': 'Failed', 'message': 'Email and password are required'}, status=400)
        email_lower = email.lower()
        try:
            user = User.objects.filter(email__iexact=email_lower).first()
            if not user:
                logger.warning(f"Login attempted with unregistered email {email_lower}")
                return JsonResponse({'status': 'Failed', 'message': 'Details mismatch'}, status=401)
            user = authenticate(request, username=user.username, password=password)
            if user:
                if user.is_active:
                    login(request, user)
                    logger.info(f"User {email_lower} logged in successfully")
                    return JsonResponse({'status': 'Success', 'redirect': '/'})
                else:
                    logger.warning(f"Login attempted by unverified user {email_lower}")
                    return JsonResponse({'status': 'Failed', 'message': 'User not verified. Please verify your email.'}, status=403)
            logger.warning(f"Invalid login attempt for {email_lower}")
            return JsonResponse({'status': 'Failed', 'message': 'Details mismatch'}, status=401)
        except Exception as e:
            logger.error(f"Unexpected error during login for {email_lower}: {e}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred during login'}, status=500)
    logger.debug("Rendering login page")
    return render(request, 'login.html')

def logout_view(request):
    username = request.user.username if request.user.is_authenticated else 'anonymous'
    logout(request)
    logger.info(f"User {username} logged out")
    response = redirect('home')
    response.delete_cookie('loggedIn')
    return response

def reset_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            logger.warning("Password reset attempt with missing email")
            return JsonResponse({'status': 'Failed', 'message': 'Email is required'}, status=400)
        email_lower = email.lower()
        user = User.objects.filter(email__iexact=email_lower).first()
        if not user:
            logger.warning(f"Password reset attempt for unregistered email {email_lower}")
            return JsonResponse({'status': 'Failed', 'message': 'Email not found'}, status=400)
        try:
            logger.debug(f"DEFAULT_FROM_EMAIL: {settings.DEFAULT_FROM_EMAIL}")
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            # Conditionally set scheme based on environment
            host = request.get_host()
            scheme = 'http' if host.startswith(('127.0.0.1', 'localhost')) else 'https'
            reset_link = f"{scheme}://{host}/reset_password_confirm/{uid}/{token}/"
            logger.debug(f"Password reset link: {reset_link}")
            subject = 'Password Reset Request'
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
                'sent_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
            })
            logger.debug(f"Rendered email content: {message}")
            email_message = EmailMessage(
                subject=subject,
                body=message,
                from_email=formataddr(('Projects Zone', settings.EMAIL_HOST_USER)),  # Use EMAIL_HOST_USER
                to=[email_lower]
            )
            email_message.content_subtype = 'html'
            email_message.send()
            logger.info(f"Password reset email sent to {email_lower}")
            return JsonResponse({'status': 'Success', 'message': 'Password reset link sent to your email'})
        except Exception as e:
            logger.error(f"Error sending password reset email to {email_lower}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'Failed to send reset email'}, status=500)
    return render(request, 'password_reset_request.html')

def password_reset_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        logger.debug(f"Decoded UID: {uid}")  # Debug UID
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
        logger.error(f"Error decoding UID or finding user: {str(e)}")
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password1 = request.POST.get('new_password1')
            new_password2 = request.POST.get('new_password2')
            if not new_password1 or not new_password2:
                logger.warning(f"Password reset attempt for {user.email} with missing password fields")
                return JsonResponse({'status': 'Failed', 'message': 'Both password fields are required'}, status=400)
            if new_password1 != new_password2:
                logger.warning(f"Password reset attempt for {user.email} with mismatched passwords")
                return JsonResponse({'status': 'Failed', 'message': 'Passwords do not match'}, status=400)
            try:
                user.set_password(new_password1)
                user.save()
                logger.info(f"Password reset successful for user {user.email}")
                return JsonResponse({'status': 'Success', 'message': 'Password reset successfully', 'redirect': '/login/'})
            except Exception as e:
                logger.error(f"Error resetting password for {user.email}: {str(e)}")
                return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
        return render(request, 'password_reset_confirm.html')
    logger.warning(f"Invalid password reset attempt: uid={uidb64}, token={token}")
    return JsonResponse({'status': 'Failed', 'message': 'Invalid or expired reset link'}, status=400)

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        if not current_password or not new_password:
            return JsonResponse({'status': 'Failed', 'message': 'Both current and new passwords are required'}, status=400)
        user = authenticate(request, username=request.user.username, password=current_password)
        if user:
            try:
                user.set_password(new_password)
                user.save()
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                logger.info(f"Password changed for user {request.user.username}")
                return JsonResponse({'status': 'Success', 'message': 'Password changed successfully'})
            except Exception as e:
                logger.error(f"Error changing password for {request.user.username}: {str(e)}")
                return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
        logger.warning(f"Invalid current password for user {request.user.username}")
        return JsonResponse({'status': 'Failed', 'message': 'Current password is incorrect'}, status=400)
    return render(request, 'change-password.html')

@login_required
def toggle_like(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            project_id = data.get('project_id')
            if not project_id:
                return JsonResponse({'status': 'Failed', 'message': 'Project ID is required'}, status=400)
            project = get_object_or_404(Project, id=project_id)
            like, created = Like.objects.get_or_create(user=request.user, project=project)
            if not created:
                like.delete()
                logger.info(f"User {request.user.username} unliked project {project.name}")
                return JsonResponse({
                    'status': 'Success',
                    'message': 'Unliked',
                    'like_count': project.like_count,
                    'action': 'unliked'
                })
            else:
                logger.info(f"User {request.user.username} liked project {project.name}")
                return JsonResponse({
                    'status': 'Success',
                    'message': 'Liked',
                    'like_count': project.like_count,
                    'action': 'liked'
                })
        except Exception as e:
            logger.error(f"Error toggling like for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def user_project_detail(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    if project.user != request.user:
        logger.warning(f"User {request.user.username} attempted to access project {project_id} they do not own")
        return JsonResponse({'status': 'Failed', 'message': 'You do not have permission to view this project'}, status=403)
    return render(request, 'user_project_detail.html', {'project': project})

@login_required
def edit_project(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            project_id = data.get('project_id')
            name = data.get('name')
            description = data.get('description', '')
            project_type = data.get('type', '')
            github_link = data.get('github_link', '')
            if not project_id or not name or not project_type:
                return JsonResponse({'status': 'Failed', 'message': 'Project ID, name, and type are required'}, status=400)
            project = get_object_or_404(Project, id=project_id)
            if project.user != request.user:
                logger.warning(f"User {request.user.username} attempted to edit project {project_id} they do not own")
                return JsonResponse({'status': 'Failed', 'message': 'You do not have permission to edit this project'}, status=403)
            if github_link and not re.match(r'^https:\/\/github\.com\/[a-zA-Z0-9-]+\/[a-zA-Z0-9-]+$', github_link):
                logger.warning(f"Invalid GitHub link provided by {request.user.username}: {github_link}")
                return JsonResponse({'status': 'Failed', 'message': 'Invalid GitHub link format'}, status=400)
            project.name = name
            project.description = description
            project.type = project_type
            project.github_link = github_link
            project.save()
            logger.info(f"Project {name} edited by user {request.user.username}")
            return JsonResponse({'status': 'Success', 'message': 'Project updated successfully'})
        except Exception as e:
            logger.error(f"Error editing project for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)

@login_required
def delete_project(request):
    if request.method == 'POST':
        try:
            import json
            data = json.loads(request.body)
            project_id = data.get('project_id')
            if not project_id:
                return JsonResponse({'status': 'Failed', 'message': 'Project ID is required'}, status=400)
            project = get_object_or_404(Project, id=project_id)
            if project.user != request.user:
                logger.warning(f"User {request.user.username} attempted to delete project {project_id} they do not own")
                return JsonResponse({'status': 'Failed', 'message': 'You do not have permission to delete this project'}, status=403)
            
            if project.image_urls:
                image_urls = project.image_urls.split(',')
                for url in image_urls:
                    if url.strip():
                        try:
                            public_id_match = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.\w+)?$', url)
                            if public_id_match:
                                public_id = public_id_match.group(1)
                                result = cloudinary.uploader.destroy(public_id, resource_type='image')
                                if result.get('result') == 'ok':
                                    logger.info(f"Deleted Cloudinary image: {public_id}")
                                else:
                                    logger.warning(f"Failed to delete Cloudinary image {public_id}: {result}")
                            else:
                                logger.warning(f"Could not extract public_id from image URL: {url}")
                        except Exception as e:
                            logger.error(f"Error deleting Cloudinary image {url}: {str(e)}")
            
            if project.video_urls:
                video_urls = project.video_urls.split(',')
                for url in video_urls:
                    if url.strip():
                        try:
                            public_id_match = re.search(r'/upload/(?:v\d+/)?(.+?)(?:\.\w+)?$', url)
                            if public_id_match:
                                public_id = public_id_match.group(1)
                                result = cloudinary.uploader.destroy(public_id, resource_type='video')
                                if result.get('result') == 'ok':
                                    logger.info(f"Deleted Cloudinary video: {public_id}")
                                else:
                                    logger.warning(f"Failed to delete Cloudinary video {public_id}: {result}")
                            else:
                                logger.warning(f"Could not extract public_id from video URL: {url}")
                        except Exception as e:
                            logger.error(f"Error deleting Cloudinary video {url}: {str(e)}")
            
            project_name = project.name
            Like.objects.filter(project=project).delete()
            logger.info(f"Deleted likes for project {project_name}")
            
            project.delete()
            logger.info(f"Project {project_name} deleted by user {request.user.username}")
            return JsonResponse({'status': 'Success', 'message': 'Project deleted successfully'})
        except Exception as e:
            logger.error(f"Error deleting project for user {request.user.username}: {str(e)}")
            return JsonResponse({'status': 'Failed', 'message': 'An unexpected error occurred'}, status=500)
    return JsonResponse({'status': 'Failed', 'message': 'Method not allowed'}, status=405)