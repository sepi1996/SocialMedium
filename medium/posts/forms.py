#Represents something through the HTML code


from wtforms import StringField, SubmitField, TextAreaField, BooleanField
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm, RecaptchaField



class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    public = BooleanField('Public Post')
    recaptcha = RecaptchaField()
    submit = SubmitField('Post')
