from app import db, login, app
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from time import time
import jwt


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True)
    username = db.Column(db.String(50), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash =generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'


    # create a method for generating a token and verifying that token

    def get_token(self, expires_in=86400):
        return jwt.encode(
            { 'user_id': self.id, 'exp': time() + expires_in },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        ).decode('utf-8')

    @staticmethod
    def verify_token(token):
        try:
            id = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms =['HS256']
            )['user_id']

        except:
            return

        return User.query.get(id)

class Record(db.Model):
    record_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, default=datetime.now().date())
    sleep = db.Column(db.Integer)
    nutrition = db.Column(db.Integer)
    hydration = db.Column(db.Integer)
    family = db.Column(db.Integer)
    friends = db.Column(db.Integer)
    intimate = db.Column(db.Integer)
    vigorous = db.Column(db.Integer)
    movement = db.Column(db.Integer)
    standing = db.Column(db.Integer)
    needed_work = db.Column(db.Integer)
    creative_work = db.Column(db.Integer)
    relaxed_state = db.Column(db.Integer)
    substance_abuse = db.Column(db.Integer)
    unhealthy_relationships = db.Column(db.Integer)
    self_harm = db.Column(db.Integer)
    mental_clarity = db.Column(db.Integer)
    notes = db.Column(db.String(500))
