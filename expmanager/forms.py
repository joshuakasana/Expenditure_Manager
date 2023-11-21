from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, IntegerField, DateField, ValidationError
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from expmanager.models import User, AuthPin

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
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
    
