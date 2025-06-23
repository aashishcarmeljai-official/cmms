import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:pass@localhost/cmms_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False