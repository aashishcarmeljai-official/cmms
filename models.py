from extensions import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Avoid using reserved word "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)