from datetime import datetime, timedelta
from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField, DateField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from expmanager import bcrypt
from expmanager.models import User, AuthPin

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=8, max=10)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    role = SelectField(u'Role', choices=[('basic', 'Record'), ('Advanced', 'Record and Update')])
    auth_pin = StringField('Auth PIN', validators=[Regexp(r'^\d*$', message="PIN must contain only numbers")])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')
        if not (8 <= len(username.data) <= 15):
            raise ValidationError('Username must be between 8 and 15 characters.')
        
    def validate_password(self, password):
        if not any(char.isalpha() for char in password.data) or \
           not any(char.isdigit() for char in password.data) or \
           not any(char.isupper() for char in password.data) or \
           not (10 <= len(password.data) <= 15):
            raise ValidationError('Password must be a mix of alpha-numeric characters, contain at least one uppercase letter, and be between 10 and 15 characters.')


    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')
        
    def validate_auth_pin(self, auth_pin):
        role_value = str(self.role.data)
        auth_pin_value = auth_pin.data
        
        if role_value == 'Advanced' and auth_pin_value is not None:
            # Check if the entered PIN matches any stored PIN in AuthPin table
            valid_pins = [pin.pin_value for pin in AuthPin.query.all()]

            if auth_pin_value not in valid_pins:
                raise ValidationError('Invalid Auth PIN. Please enter a valid PIN.')


class VerificationForm(FlaskForm):
    verification_code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

    def validate_password(self, password):
        user = User.query.filter_by(email=self.email.data).first()

        if user:
            # Implement lockout after three unsuccessful attempts
            if user.failed_login_attempts >= 3:
                raise ValidationError('Account locked due to too many unsuccessful login attempts.')

            # Implement password rotation every 90 days
            if user.last_password_change:
                days_since_last_change = (datetime.now() - user.last_password_change).days
                if days_since_last_change >= 90:
                    raise ValidationError('Password expired. Please reset your password.')

            # Implement password history to prevent reuse of last 10 passwords
            if user.check_password_history(password.data):
                raise ValidationError('You cannot reuse one of your last 10 passwords.')

            # Simulate authentication logic (you should replace this with your actual authentication logic)
            # For demonstration purposes, assume the correct password is 'password123'
            if not bcrypt.check_password_hash(user.password, password.data):
                user.failed_login_attempts += 1
                user.save()  # Save the updated user information
                raise ValidationError('Incorrect password. Attempts remaining: {}'.format(3 - user.failed_login_attempts))
            else:
                # Successful login, reset failed login attempts
                user.failed_login_attempts = 0
                user.last_password_change = datetime.now()
                user.add_password_to_history(password.data)  # Add the new password to the history
                user.save()  # Save the updated user information

        else:
            raise ValidationError('Invalid username.')


class RecordExpenditureForm(FlaskForm):
    expense_type = SelectField(u'Expense Type', choices=[('Food', 'Food'), ('Travels', 'Transport'), ('Medicine', 'Medicine')]) #(value, label)
    amount = IntegerField('Amount',
                          validators=[DataRequired()])
    date = DateField('Date',
                     validators=[DataRequired()])
    submit = SubmitField('Record')

# class UpdateExpenditureForm(FlaskForm):
#     expense_type = StringField('Expense Type',
#                                validators=[DataRequired()])
#     amount = IntegerField('Amount',
#                           validators=[DataRequired()])
#     date = DateField('Date',
#                      validators=[DataRequired()])
    

class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=8, max=10)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

    def validate_new_password(self, new_password):
        if not any(char.isalpha() for char in new_password.data) or \
           not any(char.isdigit() for char in new_password.data) or \
           not any(char.isupper() for char in new_password.data) or \
           not (10 <= len(new_password.data) <= 15):
            raise ValidationError('Password must be a mix of alpha-numeric characters, contain at least one uppercase letter, and be between 10 and 15 characters.')