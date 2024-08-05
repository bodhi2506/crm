import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '12345678'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///crm.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False