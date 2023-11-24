from datetime import datetime
from flask import render_template, url_for, flash, redirect, request, jsonify
from expmanager import app, db, bcrypt, s, mail
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
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
        user = User(
            username=form.username.data, 
            email=form.email.data, 
            role=form.role.data,
            auth_pin=form.auth_pin.data, 
            password=hashed_password, 
            last_password_change=datetime.utcnow()
        )
        user.add_password_to_history(new_password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! Please check your email for verification.', 'success')
        flash('Login!', 'success')        
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
   items = Expense.query.all()
   return render_template('update.html', items=items)



#Forget Password route
@app.route("/change_password", methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        # Check if the current password is correct
        if bcrypt.check_password_hash(current_user.password, form.current_password.data):
            # Update the password and password history
            if current_user.check_password_history(form.new_password.data):
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

@app.route("/update/<int:item_id>", methods=['GET', 'POST'])
@login_required
def update_item(item_id):
    # Check if the current user has permission to update the item
    if current_user.role != 'Advanced':
        flash(f'You do not have access to update records', 'danger')
        return redirect(url_for('dashboard'))

    form = RecordExpenditureForm()
     # Fetch the expense item by item_id
    expense = Expense.query.get(item_id)
    
    if expense is None:
        flash('Expense not found', 'danger')
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        # The form has been submitted and is valid
        new_expense_type = form.expense_type.data
        new_amount = form.amount.data
        new_date = form.date.data

        # Update the expense fields as needed
        expense.expense_type = new_expense_type
        expense.amount = new_amount
        expense.date = new_date

        # Commit the changes to the database
        db.session.commit()

        flash('Expense updated successfully', 'success')
        return redirect(url_for('update'))

    # Render the update form with the existing expense details
    return render_template('update_record.html', form=form)

@app.route("/delete/<int:item_id>", methods=['DELETE'])
@login_required
def delete_item(item_id):
    # Check if the current user has permission to delete the item
    if current_user.role != 'Advanced':
        return jsonify({'message': 'You do not have permission to delete this item'}), 403

    # Try to find the expense to delete
    expense = Expense.query.get(item_id)
    if expense:
        # Delete the expense from the database
        db.session.delete(expense)
        db.session.commit()
        return jsonify({'message': 'Expense deleted successfully'}), 200
    else:
        return jsonify({'message': 'Expense not found'}), 404



# # Route for sending email verification
# @app.route('/send_verification/<email>')
# def send_verification(email):
#     user = User.query.filter_by(email=email).first()
#     if user:
#         # Check if the user is already verified
#         if user.is_verified:
#             flash('Email is already verified.', 'info')
#             return redirect(url_for('index'))

#         # Generate a unique token for email verification
#         token = s.dumps(email, salt='email-verification')
#         verification_url = url_for('verify_email', token=token, _external=True)
        
#         # Send email with verification link
#         msg = Message('Email Verification', recipients=[email])
#         msg.body = f'To verify your email, please click the following link: {verification_url}'
#         mail.send(msg)

#         flash('Email verification link sent. Please check your email.', 'success')
#         return redirect(url_for('index'))
#     else:
#         flash('User not found.', 'danger')
#         return redirect(url_for('index'))


# # Route for verifying email with token
# @app.route('/verify_email/<token>', methods=['GET', 'POST'])
# def verify_email(token):
#     try:
#         email = s.loads(token, salt='email-verification', max_age=3600)
#         user = User.query.filter_by(email=email).first()

#         if user and not user.is_verified:
#             user.is_verified = True
#             db.session.commit()

#             flash('Email verified successfully! You can now log in.', 'success')
#             return redirect(url_for('login'))  # Redirect to your login route
#         elif user and user.is_verified:
#             flash('Email is already verified.', 'info')
#             return redirect(url_for('login'))  # Redirect to your login route
#         else:
#             flash('Invalid token or user not found.', 'danger')
#             return redirect(url_for('index'))
#     except Exception as e:
#         flash('Invalid or expired token.', 'danger')
#         return redirect(url_for('index'))