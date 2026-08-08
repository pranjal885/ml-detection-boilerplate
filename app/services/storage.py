import os
import uuid
import logging
from werkzeug.utils import secure_filename
from flask import current_app

logger = logging.getLogger(__name__)

def save_file_to_disk(file_storage_obj):
    """
    Saves an uploaded file to the configured uploads folder on disk.
    Generates a unique disk name using UUID to prevent collisions and overwrites.
    
    Args:
        file_storage_obj (FileStorage): The file object from request.files.
        
    Returns:
        tuple: (original_filename, secure_disk_filename, file_size_bytes, content_mime_type)
    """
    upload_dir = current_app.config['UPLOAD_FOLDER']
    
    # Ensure directory exists
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
        logger.info(f"Created file upload directory at: {upload_dir}")
        
    # Sanitize the input filename (prevents path injection attacks like ../../etc)
    orig_filename = secure_filename(file_storage_obj.filename)
    if not orig_filename:
        orig_filename = f"uploaded_file_{uuid.uuid4().hex[:8]}"
        
    # Generate unique UUID-based filename on disk preserving extension
    _, ext = os.path.splitext(orig_filename)
    disk_filename = f"{uuid.uuid4().hex}{ext}"
    
    # Full absolute path for saving
    dest_path = os.path.join(upload_dir, disk_filename)
    
    # Save the file object
    file_storage_obj.save(dest_path)
    
    # Retrieve metadata details
    file_size = os.path.getsize(dest_path)
    mime_type = file_storage_obj.content_type or 'application/octet-stream'
    
    logger.info(f"File saved: {orig_filename} -> {disk_filename} ({file_size} bytes)")
    
    return orig_filename, disk_filename, file_size, mime_type

def delete_file_from_disk(disk_filename):
    """
    Physically removes a file from the server disk storage.
    
    Args:
        disk_filename (str): The unique UUID-based filename on disk.
        
    Returns:
        bool: True if file was found and removed, False otherwise.
    """
    upload_dir = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_dir, disk_filename)
    
    # Safe boundary check: ensure the path is within the designated upload directory
    real_path = os.path.abspath(file_path)
    real_upload_dir = os.path.abspath(upload_dir)
    if not real_path.startswith(real_upload_dir):
        logger.warning(f"Path traversal block: Blocked deletion of {real_path} outside upload directory.")
        return False
        
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"Physical file deleted: {disk_filename}")
            return True
        except OSError as e:
            logger.error(f"Error deleting file {disk_filename} from disk: {e}")
            return False
            
    logger.warning(f"File not found on disk: {disk_filename}")
    return False

def get_disk_file_path(disk_filename):
    """
    Gets the absolute path of a file, verifying it lies inside the upload boundary.
    
    Args:
        disk_filename (str): The unique UUID-based filename on disk.
        
    Returns:
        str: Absolute path if safe, None otherwise.
    """
    upload_dir = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_dir, disk_filename)
    
    real_path = os.path.abspath(file_path)
    real_upload_dir = os.path.abspath(upload_dir)
    
    if not real_path.startswith(real_upload_dir):
        logger.warning(f"Access attempt blocked to path outside upload folder: {real_path}")
        return None
        
    return file_path
