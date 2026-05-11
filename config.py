import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'default-key-for-dev')
    # Se DATABASE_URL non esiste (locale), usa SQLite
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///unisafevote.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
