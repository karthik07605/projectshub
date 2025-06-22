import cloudinary.uploader
import logging

logger = logging.getLogger(__name__)

def upload_to_cloudinary(file, file_name, resource_type='image'):
    try:
        upload_result = cloudinary.uploader.upload(
            file,
            public_id=file_name,
            resource_type=resource_type,
            folder='project_uploads/',
            use_filename=True,
            unique_filename=False,
            overwrite=True,
        )
        return upload_result['secure_url']
    except Exception as e:
        logger.error(f"Upload to Cloudinary failed: {e}")
        raise
