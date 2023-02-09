from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, IntegerField, HiddenField, PasswordField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class CustomerForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    mobile_number = IntegerField('Mobile Number', validators=[DataRequired()])
    submit = SubmitField('Sign In')
    customer_id = HiddenField()


class CustomerModifyForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    mobile_number = IntegerField('Mobile Number', validators=[DataRequired()])
    submit = SubmitField('Modify')


class AccountForm(FlaskForm):
    account_type = SelectField('Account Type', choices=[('Current Account', 'Current Account'), ('Savings Account', 'Savings Account'), ('Salary Account', 'Salary Account')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    balance = IntegerField('Starting balance', validators=[DataRequired()])
    submit = SubmitField('Create Account')
    account_no = HiddenField()


class AccountModifyForm(FlaskForm):
    account_type = SelectField('Account Type', choices=[('Current Account', 'Current Account'), ('Savings Account', 'Savings Account'), ('Salary Account', 'Salary Account')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Modify Account')


class TransactionForm(FlaskForm):
    customer_account_no = HiddenField()
    transaction_account_no = IntegerField('Transfer account number', validators=[DataRequired()])
    amount = IntegerField('Transfer Amount', validators=[DataRequired()])
    password = PasswordField('Account Password', validators=[DataRequired()])
    submit = SubmitField('Transfer')