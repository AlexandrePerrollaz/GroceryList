from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import logging

# Initialize Flask app
grocery_list = Flask(__name__)
grocery_list.secret_key = 'your_secret_key'

# Configure SQLite database
grocery_list.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
grocery_list.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and migration
db = SQLAlchemy(grocery_list)
migrate = Migrate(grocery_list, db)

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

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(80), db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='unique_user_category'),)

# User loader
login_manager = LoginManager(grocery_list)
login_manager.login_view = 'login'

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
    # Fetch categories and items for the user
    user_categories = Category.query.filter_by(user_id=current_user.id).all()
    user_items = GroceryItem.query.filter_by(user_id=current_user.id).all()

    # Group items by categories
    user_list = {category: [] for category in user_categories}
    for item in user_items:
        for category in user_categories:
            if item.category == category.name:
                user_list[category].append(item)
                break

    # Handle POST requests
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_item':
            category_id = request.form.get('category_id')
            item_name = request.form.get('item_name')

            if category_id and item_name:
                category = Category.query.get(int(category_id))
                if category:
                    new_item = GroceryItem(user_id=current_user.id, category=category.name, name=item_name)
                    db.session.add(new_item)
                    db.session.commit()
                    flash('Item added successfully!', 'success')
                else:
                    flash('Invalid category selected.', 'danger')
            else:
                flash('Both category and item name are required!', 'danger')

        elif action == 'add_category':
            new_category = request.form.get('new_category')
            if new_category:
                existing_category = Category.query.filter_by(user_id=current_user.id, name=new_category).first()
                if not existing_category:
                    new_category_entry = Category(user_id=current_user.id, name=new_category)
                    db.session.add(new_category_entry)
                    db.session.commit()
                    flash('Category added successfully!', 'success')
                else:
                    flash('Category already exists!', 'danger')

        return redirect(url_for('index'))

    return render_template('index.html', grocery_data=user_list)

@grocery_list.route('/delete_category', methods=['POST'])
@login_required
def delete_category():
    category_id = request.form.get('category_id')
    if not category_id:
        flash('No category ID provided.', 'danger')
        return redirect(url_for('index'))

    category = Category.query.get(int(category_id))
    if category:
        GroceryItem.query.filter_by(user_id=current_user.id, category=category.name).delete()
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully!', 'success')
    else:
        flash('Category not found.', 'danger')

    return redirect(url_for('index'))

@grocery_list.route('/edit_category', methods=['POST'])
@login_required
def edit_category():
    old_name = request.form.get('old_name')
    new_name = request.form.get('new_name')

    if not old_name or not new_name:
        flash('Both old and new category names are required!', 'danger')
        return redirect(url_for('index'))

    category = Category.query.filter_by(user_id=current_user.id, name=old_name).first()
    if category:
        category.name = new_name
        # Update associated items
        GroceryItem.query.filter_by(user_id=current_user.id, category=old_name).update({'category': new_name})
        db.session.commit()
        flash('Category updated successfully!', 'success')
    else:
        flash('Category not found!', 'danger')

    return redirect(url_for('index'))

@grocery_list.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    item_id = request.form.get('item_id')
    if not item_id:
        flash('No item ID provided.', 'danger')
        return redirect(url_for('index'))

    item = GroceryItem.query.get(int(item_id))
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted successfully!', 'success')
    else:
        flash('Item not found.', 'danger')

    return redirect(url_for('index'))


if __name__ == '__main__':
    grocery_list.run(host='0.0.0.0', port=5000, debug=False)
