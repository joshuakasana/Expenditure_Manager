from datetime import datetime
from expmanager import db, login_manager
from flask_login import UserMixin

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
    auth_pin = db.Column(db.String(6), default=None)  # Adjusted to a specific length (e.g., 6 digits)
    password = db.Column(db.String(60), nullable=False)
    expenses = db.relationship('Expense', backref='author', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}', '{self.auth_pin}', '{self.password}')"

class Expense(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    expense_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # Adjusted to a numeric type
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Expense('{self.expense_type}', '{self.amount}', '{self.date}')"
