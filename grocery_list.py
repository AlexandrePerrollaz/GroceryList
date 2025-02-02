from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize Flask app
grocery_list = Flask(__name__)
grocery_list.secret_key = 'your_secret_key'

# Configure SQLite database
grocery_list.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
grocery_list.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(grocery_list)

# Initialize Flask-Login
login_manager = LoginManager(grocery_list)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.String(80), primary_key=True)
    password_hash = db.Column(db.String(200), nullable=False)

class GroceryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100))
    name = db.Column(db.String(100))
    checked = db.Column(db.Boolean, default=False)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(username):
    return User.query.get(username)

# Routes
@grocery_list.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(id=username).first():
            flash('Username already exists.', 'danger')
        else:
            new_user = User(id=username, password_hash=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@grocery_list.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(id=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@grocery_list.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@grocery_list.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_items = GroceryItem.query.filter_by(user_id=current_user.id).all()
    categorized_items = {}
    for item in user_items:
        categorized_items.setdefault(item.category, []).append(item)

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'toggle':
            item_id = int(request.form.get('item_id'))
            item = GroceryItem.query.get(item_id)
            if item:
                item.checked = not item.checked
                db.session.commit()
        elif action == 'add_item':
            category = request.form.get('category')
            item_name = request.form.get('item_name')
            if category and item_name:
                new_item = GroceryItem(user_id=current_user.id, category=category, name=item_name)
                db.session.add(new_item)
                db.session.commit()
        elif action == 'add_category':
            new_category = request.form.get('new_category')
            # Categories are just labels; no need to create them explicitly in this structure

        return redirect(url_for('index'))

    return render_template('index.html', grocery_data=categorized_items)

@grocery_list.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    item_id = int(request.form.get('item_id'))
    item = GroceryItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted successfully!', 'success')
    return redirect(url_for('index'))

@grocery_list.route('/edit_item', methods=['POST'])
@login_required
def edit_item():
    item_id = int(request.form.get('item_id'))
    new_name = request.form.get('new_name')
    item = GroceryItem.query.get(item_id)
    if item:
        item.name = new_name
        db.session.commit()
        flash('Item updated successfully!', 'success')
    return redirect(url_for('index'))

@grocery_list.route('/edit_category', methods=['POST'])
@login_required
def edit_category():
    old_name = request.form.get('old_name')
    new_name = request.form.get('new_name')
    items = GroceryItem.query.filter_by(user_id=current_user.id, category=old_name).all()
    for item in items:
        item.category = new_name
    db.session.commit()
    flash('Category updated successfully!', 'success')
    return redirect(url_for('index'))

# Create database tables
if __name__ == '__main__':
    db.create_all()  # Create tables if they don't exist
    grocery_list.run(host='0.0.0.0', port=5000, debug=False)
