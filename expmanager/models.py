from datetime import datetime, timedelta
from expmanager import db, login_manager, bcrypt
from flask_login import UserMixin
from sqlalchemy import func

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class AuthPin(db.Model): # Storing pins: 108010, 373737, 400400
    id = db.Column(db.Integer, primary_key=True)
    pin_value = db.Column(db.String(5), unique=True, nullable=False)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    auth_pin = db.Column(db.String(6), unique=True, default=None)  # Adjusted to a specific length (e.g., 6 digits)
    password = db.Column(db.String(60), nullable=False)
    password_history = db.Column(db.String(128), nullable=True)
    last_password_change = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    # is_verified = db.Column(db.Boolean, default=False)
    expenses = db.relationship('Expense', backref='author', lazy=True)
    
    def set_password(self, new_password):
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Set the hashed password and update the timestamp
        self.password = hashed_password
        self.last_password_change = datetime.utcnow()

    def add_password_to_history(self, new_password):
        # Add the new password to the password history
        # This assumes that the password history is stored as a comma-separated string
        if self.password_history is None:
            self.password_history = new_password
        else:
            # Limit the history to the last 10 passwords
            history_list = self.password_history.split(',')
            history_list = [new_password] + history_list[:9]
            self.password_history = ','.join(history_list)

    def check_password_history(self, password): #On resetting or changing the password
        # Check if the provided password is in the password history
        if self.password_history is not None:
            history_list = self.password_history.split(',')
            return password in history_list
        return False
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}', '{self.auth_pin}', '{self.password}')"

class Expense(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    expense_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # Adjusted to a numeric type
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def get_username(self):
        user = User.query.get(self.user_id)
        return user.username if user else None
    
    @staticmethod
    def get_total_expenditure():
        return db.session.query(func.sum(Expense.amount)).scalar()

    @staticmethod
    def get_total_expenses_by_type(expense_type):
        return db.session.query(func.sum(Expense.amount)).filter_by(expense_type=expense_type).scalar()

    @staticmethod
    def get_monthly_expenses():
        current_date = datetime.utcnow()
        last_day_of_month = (datetime(current_date.year, current_date.month, 1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)

        start_date = datetime(current_date.year, current_date.month, 1)
        end_date = last_day_of_month + timedelta(days=1)

        return db.session.query(func.sum(Expense.amount)).filter(
            Expense.date >= start_date,
            Expense.date < end_date
        ).scalar()

    def __repr__(self):
        return f"Expense('{self.expense_type}', '{self.amount}', '{self.date}')"
