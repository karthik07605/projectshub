from django.core.mail import EmailMessage
from django.conf import settings
from email.utils import formataddr
import logging

logger = logging.getLogger(__name__)

def send_otp_email(data, otp):
    email = data.get('email')
    if not email:
        logger.error("No email provided for OTP")
        raise ValueError("Email is required")
    try:
        subject = 'Your OTP for SeniorSync Projects'
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); padding: 30px;">
                    <h2 style="text-align: center; color: #4CAF50;">OTP Verification</h2>
                    <p style="font-size: 16px; color: #333333;">Dear user,</p>
                    <p style="font-size: 14px; color: #333333;">
                        Your One-Time Password (OTP) for <strong>SeniorSync Projects</strong> is:
                    </p>
                    <br>
                    <div style="text-align: center; margin: 20px 0;">
                        <span style="display: inline-block; background-color: #e0f7fa; color: #00796b; font-size: 24px; font-weight: bold; padding: 10px 20px; border-radius: 8px; letter-spacing: 2px;">
                            {otp}
                        </span>
                    </div>
                    <br>
                    <p style="font-size: 14px; color: #555555;">
                        This OTP is valid for <strong>1 hour</strong>. Please do not share it with anyone.
                    </p>
                    <p style="font-size: 14px; color: #555555;">If you did not request this, please ignore this email.</p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #dddddd;">
                    <p style="font-size: 14px; color: #999999; text-align: center;">
                        Thank you for using <strong>SeniorSync Projects</strong>!<br>
                        <em>This is an automated message. Please do not reply.</em>
                    </p>
                </div>
            </body>
        </html>
        """
        email_msg = EmailMessage(
            subject,
            body,
            formataddr(("SeniorSync Projects", settings.EMAIL_HOST_USER)),  # Friendly sender name
            [email]
        )
        email_msg.content_subtype = 'html'
        email_msg.send(fail_silently=False)
        logger.info(f"OTP email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {str(e)}")
        raise
