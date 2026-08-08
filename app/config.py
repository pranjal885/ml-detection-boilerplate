import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Root directory of the project
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))

class Config:
    # Required in production. Local development may set SECRET_KEY in the environment
    # or use this explicit dev-only fallback when running locally without a .env file.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-secret-key-change-me'

    # Database Configuration (MySQL with SQLite development fallback)
    DB_USER = os.environ.get('DB_USER')
    DB_PASSWORD = os.environ.get('DB_PASSWORD')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '3306')
    DB_NAME = os.environ.get('DB_NAME')

    if DB_USER and DB_NAME:
        # Use PyMySQL driver to connect to MySQL database
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD or ''}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # Fallback to local SQLite database if MySQL settings aren't provided
        sqlite_dir = os.path.join(ROOT_DIR, 'instance')
        if not os.path.exists(sqlite_dir):
            os.makedirs(sqlite_dir)
        sqlite_db = os.path.join(sqlite_dir, 'cloudvault.db')
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{sqlite_db}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File Storage Configurations
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(ROOT_DIR, 'uploads'))
    # Max file size limit: 50 Megabytes
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024
