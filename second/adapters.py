from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User
from second.models import Profile

class NoUsernameAdapter(DefaultAccountAdapter):
    def populate_username(self, request, user):
        if not user.username:
            base_username = user.email.split('@')[0] if user.email else get_random_string(10)
            username = base_username
            counter = 1
            while User.objects.filter(username__iexact=username).exists():
                username = f"{base_username}{counter}"
                counter += 1
            user.username = username

class MySocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        # Create or update profile for the user
        profile, created = Profile.objects.get_or_create(
            user=user,
            defaults={
                'name': sociallogin.account.extra_data.get('name', user.email.split('@')[0]),
                'mobile': ''
            }
        )
        if not created and not profile.name:
            profile.name = sociallogin.account.extra_data.get('name', user.email.split('@')[0])
            profile.save()
        return user