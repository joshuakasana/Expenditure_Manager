from flask import render_template, url_for, flash, redirect, request
from expmanager import app, db, bcrypt
from expmanager.forms import RegistrationForm, LoginForm, RecordExpenditureForm, VerificationForm
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
    return render_template('dashboard.html', title="Dashboard")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, role=form.role.data, auth_pin=form.auth_pin.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been created! please login', 'success')
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

@app.route('/record')
@login_required
def record():
    form = RecordExpenditureForm()
    if form.validate_on_submit():
        record = Expense(expense_type=form.expense_type.data, amount=form.amount.data, date=form.date.data, user_id=current_user.id)
        db.session.add(record)
        db.session.commit()
        flash(f'Expense {{ form.expense_type }} has been recorded')
    return render_template('record.html', title="Record - Expenditure", form=form)


@app.route('/update')
@login_required
def update():
   return render_template('update.html')

@app.route("/logout")
def logout():
    logout_user()
    return render_template('index.html', title='Home')


