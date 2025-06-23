from flask import Flask, render_template, redirect, url_for, request, flash
from extensions import db, login_manager
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
import os

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("Username already taken")
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully. Please log in.")
        return redirect(url_for('login'))
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# Maps
@app.route('/maps')
@login_required
def maps():
    return render_template('maps.html', user=current_user)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# One-time DB init route with optional admin user creation
@app.route("/db_init")
def db_init():
    secret = request.args.get("secret")
    if secret != "mysecretkey":  # Replace with strong secret in production
        return "⛔ Unauthorized", 401

    with app.app_context():
        db.create_all()

        # Optional: create default admin user if not exists
        if not User.query.filter_by(username="admin").first():
            admin_pw = generate_password_hash("admin123")
            admin = User(username="admin", password=admin_pw)
            db.session.add(admin)
            db.session.commit()
            return "✅ DB initialized and admin user created! (username: admin, password: admin123)"

    return "✅ Database tables created successfully!"

# Run app locally
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)