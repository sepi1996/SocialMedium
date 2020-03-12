#Represents something through the HTML code

from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, Regexp
from flask_login import current_user
from medium.models import User
from password_strength import PasswordPolicy


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=25)])
    email = StringField('Email',
                        validators=[DataRequired(), Email(), Length(min=5, max=100)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already in use. Choose another one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already in use. Choose another one.')
'''
    def validate_password(self, password):
        policy = PasswordPolicy.from_names(
            length=8,  # min length: 8
            uppercase=2,  # need min. 2 uppercase letters
            numbers=1,  # need min. 2 digits
            special=1,  # need min. 2 special characters
            nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
        )
        if policy.test(password):
            raise ValidationError('Please create a more secure password with at least: -8 caracters.\
                                 -2 Uppercase. -1 Number. -1 Special character. -2 Non-letter characters')
'''

class LoginForm(FlaskForm):
    username = StringField('Username',
                        validators=[DataRequired(), Length(min=2, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=25)])
    email = StringField('Email',
                        validators=[DataRequired(), Email(), Length(min=5, max=100)])
    submit = SubmitField('Update')
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already in use. Choose another one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already in use. Choose another one.')

class RequestResetForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=25)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is None:
            raise ValidationError('There is no account with that username. You must register first.')

class TokenForm(FlaskForm):
    token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
    remember = BooleanField('Remember new device')
    submit = SubmitField('Login')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class ChallengeForm(FlaskForm):
    personalPosts = StringField('Number of personal posts that you have', validators=
        [Optional(), Regexp('^[0-9]*$', message='Just numbers are allowed')])
    registrationYear = StringField('Year you created your account', validators=
        [Optional(), Regexp('^[0-9]*$', message='Just numbers are allowed'), Length(4, 4, message='Year must have 4 characters')])
    registrationMonth = StringField('Month you created your account', validators=
        [Optional(), Regexp('^[0-9]*$', message='Just numbers are allowed'), Length(2, 2, message='Month must have 2 characters')])
    token = StringField('Token', validators=[Optional(), Length(6, 6, message='Token must have 6 characters')])
    submit = SubmitField('Send answers')