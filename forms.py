from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, IntegerField, HiddenField, PasswordField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class CustomerForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    mobile_number = IntegerField('Mobile Number', validators=[DataRequired()])
    submit = SubmitField('Submit')
    customer_id = HiddenField()


class AccountForm(FlaskForm):
    account_type = SelectField('Choose a category', choices=[('Current Account', 'Current Account'), ('Savings Account', 'Savings Account'), ('Salary Account', 'Salary Account')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    balance = IntegerField()
    submit = SubmitField('Submit')
    account_no = HiddenField()