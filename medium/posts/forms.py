#Represents something through the HTML code


from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField, validators
from wtforms.validators import DataRequired
from flask_wtf import FlaskForm, RecaptchaField


POST_TYPE = [(0,'Private'),(1,'Personal'),(2,'Public')]

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    post_type = SelectField('post_type', [validators.input_required("Please choose a type.")], choices = POST_TYPE, coerce=int)
    recaptcha = RecaptchaField()
    submit = SubmitField('Post')

class SearchForm(FlaskForm):
    post_word = StringField('Title', validators=[DataRequired()])
    submit = SubmitField('Search Post')