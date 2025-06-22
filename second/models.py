from django.db import models
from django.contrib.auth.models import User
import random

class EmailOTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.save()

    def __str__(self):
        return f"{self.email} - {self.otp}"

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    mobile = models.CharField(max_length=15)

    def __str__(self):
        return f"{self.name}'s Profile"

class Project(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    image_urls = models.TextField(blank=True, null=True)
    video_urls = models.TextField(blank=True, null=True)
    github_link = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if self.image_urls:
            cleaned_urls = [url.strip() for url in self.image_urls.split(',') if url.strip() and url.startswith('https://')]
            self.image_urls = ','.join(cleaned_urls)
        if self.video_urls:
            cleaned_urls = [url.strip() for url in self.video_urls.split(',') if url.strip() and url.startswith('https://')]
            self.video_urls = ','.join(cleaned_urls)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name} ({self.type}) by {self.user.username}"

    @property
    def images_list(self):
        return self.image_urls.split(',') if self.image_urls else []

    @property
    def videos_list(self):
        return self.video_urls.split(',') if self.video_urls else []

    @property
    def like_count(self):
        return self.likes.count()

class Like(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='likes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'project')

    def __str__(self):
        return f"{self.user.username} likes {self.project.name}"

class TeamMemberRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    project_name = models.CharField(max_length=255)
    description = models.TextField()
    team_size = models.PositiveIntegerField()
    required_skills = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.project_name} by {self.user.username}"

    @property
    def skills_list(self):
        return [skill.strip() for skill in self.required_skills.split(',') if skill.strip()]

class TeamMemberApplication(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Accepted', 'Accepted'),
        ('Rejected', 'Rejected'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    team_request = models.ForeignKey(TeamMemberRequest, on_delete=models.CASCADE, related_name='applications')
    message = models.TextField(blank=True, null=True)
    applied_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')

    class Meta:
        unique_together = ('user', 'team_request')

    def __str__(self):
        return f"{self.user.username} applied to {self.team_request.project_name}"

class Notification(models.Model):
    STATUS_CHOICES = (
        ('Pending', 'Pending'),
        ('Accepted', 'Accepted'),
        ('Rejected', 'Rejected'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    team_request = models.ForeignKey(TeamMemberRequest, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.team_request.project_name} ({self.status})"