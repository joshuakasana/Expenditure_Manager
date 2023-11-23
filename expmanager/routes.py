from datetime import datetime
from flask import render_template, url_for, flash, redirect, request
from expmanager import app, db, bcrypt
from flask_sqlalchemy import SQLAlchemy
from expmanager.forms import RegistrationForm, LoginForm, RecordExpenditureForm, UpdateAccountForm, VerificationForm, ChangePasswordForm
from expmanager.models import User, Expense
from flask_login import login_user, current_user, logout_user, login_required



@app.route('/')
@app.route('/index')
def index():
    bg_img = url_for('static', filename='pics/money-calc.png')
    return render_template('index.html', title='Home', bg_img=bg_img)

@app.route('/dashboard')
@login_required
def dashboard():
    items = Expense.query.all()
    total_expenditure = Expense.get_total_expenditure()
    monthly_expenses = Expense.get_monthly_expenses()
    # Get all distinct expense types
    expense_types = db.session.query(Expense.expense_type).distinct().all()

    # Create a dictionary to store total expenses for each type
    total_expenses_by_type = {}
    for expense_type in expense_types:
        total_expenses_by_type[expense_type[0]] = Expense.get_total_expenses_by_type(expense_type[0])

    return render_template('dashboard.html', title="Dashboard",
                           total_expenditure=total_expenditure,
                           monthly_expenses=monthly_expenses,
                           total_expenses_by_type=total_expenses_by_type)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, role=form.role.data,
                    auth_pin=form.auth_pin.data, password=hashed_password, last_password_change=datetime.utcnow())
        user.add_password_to_history(new_password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created! Please login', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        # print("Email",form.email.data)
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

@app.route("/record", methods=['GET', 'POST'])
@login_required
def record():
    form = RecordExpenditureForm()
    if form.validate_on_submit():
        record = Expense(expense_type=form.expense_type.data, amount=form.amount.data, date=form.date.data, user_id=current_user.id)
        db.session.add(record)
        try:
            db.session.commit()
            flash(f'Expense {form.expense_type.data} has been recorded', 'success')
            return redirect(url_for('dashboard'))
        except SQLAlchemy.SQLAlchemyError as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
    return render_template('record.html', title="Record - Expenditure", form=form)


@app.route("/update", methods=['GET', 'POST'])
@login_required
def update():
   if current_user.role != 'Advanced':
        flash(f'You do not have access to update records', 'danger')
        return redirect(url_for('dashboard'))
   
   return render_template('update.html')



#Forget Password route
@app.route("/change_password", methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Check if the current password is correct
        if bcrypt.check_password_hash(current_user.password, form.current_password.data):
            # Update the password and password history
            if current_user.check_password_history(form.current_password.data):
                flash(f'You cannot reuse one of your last 10 passwords.', 'danger')
                return redirect(url_for('change_password'))
            current_user.set_password(form.new_password.data)
            current_user.add_password_to_history(form.new_password.data)
            # Commit changes to the database
            try:
                db.session.commit()
                flash(f'Your password has been changed successfully!', 'success')
                return redirect(url_for('dashboard'))
            except SQLAlchemy.SQLAlchemyError as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'danger')       
        else:
            flash('Incorrect current password. Please try again.', 'danger')

    return render_template('change_password.html', title='Change Password', form=form)
