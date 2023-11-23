# auth_service.py

from datetime import datetime
from flask_login import login_user, current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField, DateField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from expmanager import db, login_manager, bcrypt
from models import User

class AuthService:
    @staticmethod
    def authenticate_user(email, password):
        user = User.query.filter_by(email=email).first()

        if user:
            # Authentication logic...

            # Implement lockout after three unsuccessful attempts
            if user.failed_login_attempts >= 3:
                raise ValidationError('Account locked due to too many unsuccessful login attempts.')

            # Implement password rotation every 90 days
            if user.last_password_change:
                days_since_last_change = (datetime.now() - user.last_password_change).days
                if days_since_last_change >= 90:
                    raise ValidationError('Password expired. Please reset your password.')

            # Implement password history to prevent reuse of last 10 passwords
            if user.check_password_history(password):
                raise ValidationError('You cannot reuse one of your last 10 passwords.')

            # Simulate authentication logic (you should replace this with your actual authentication logic)
            # For demonstration purposes, assume the correct password is 'password123'
            if not bcrypt.check_password_hash(user.password, password):
                user.failed_login_attempts += 1
                user.save()  # Save the updated user information
                raise ValidationError('Incorrect password. Attempts remaining: {}'.format(3 - user.failed_login_attempts))
            else:
                # Successful login, reset failed login attempts
                user.failed_login_attempts = 0
                user.last_password_change = datetime.utcnow()
                user.add_password_to_history(password)  # Add the new password to the history
                user.save()  # Save the updated user information

                # Log in the user using Flask-Login
                login_user(user, remember=True)

                return user  # Return the authenticated user
        else:
            return None
