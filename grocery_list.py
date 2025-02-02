from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import threading
# Initialize Flask grocery_list
grocery_list = Flask(__name__)
grocery_list.secret_key = 'your_secret_key'

# Initialize Flask-Login
login_manager = LoginManager(grocery_list)
login_manager.login_view = 'login'

# JSON files
USERS_FILE = "users.json"
DATA_FILE = "grocery_data.json"

# Helper functions to load and save data
def load_json(file, default_data):
    if os.path.exists(file):
        with open(file, 'r') as f:
            return json.load(f)
    return default_data

def save_json(file, data):
    with open(file, 'w') as f:
        json.dump(data, f, indent=4)

# Load users and data
users_data = load_json(USERS_FILE, {})
grocery_data = load_json(DATA_FILE, {})

# Flask-Login user model
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if username in users_data:
        return User(username)
    return None

# Flask routes for authentication
@grocery_list.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_data:
            flash('Username already exists.', 'danger')
        else:
            users_data[username] = generate_password_hash(password)
            grocery_data[username] = {"Fruits": [], "Dairy": [], "Bakery": []}
            save_json(USERS_FILE, users_data)
            save_json(DATA_FILE, grocery_data)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@grocery_list.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_data and check_password_hash(users_data[username], password):
            login_user(User(username))
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

# Flask routes for grocery list
@grocery_list.route('/', methods=['GET', 'POST'])
@login_required
def index():
    user_list = grocery_data.get(current_user.id, {})

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'toggle':
            category = request.form.get('category')
            index = int(request.form.get('index'))
            user_list[category][index]['checked'] = not user_list[category][index]['checked']
        elif action == 'add_item':
            category = request.form.get('category')
            item_name = request.form.get('item_name')
            if category and item_name:
                user_list[category].grocery_listend({"name": item_name, "checked": False})
        elif action == 'add_category':
            new_category = request.form.get('new_category')
            if new_category and new_category not in user_list:
                user_list[new_category] = []

        grocery_data[current_user.id] = user_list
        save_json(DATA_FILE, grocery_data)
        return redirect(url_for('index'))

    return render_template('index.html', grocery_data=user_list)

# Add new routes for editing

@grocery_list.route('/edit_item', methods=['POST'])
@login_required
def edit_item():
    category = request.form.get('category')
    old_index = int(request.form.get('old_index'))
    new_name = request.form.get('new_name')
    new_category = request.form.get('new_category', category)

    # Move or edit item
    if category in grocery_data[current_user.id]:
        item = grocery_data[current_user.id][category].pop(old_index)
        item['name'] = new_name
        if new_category != category:
            grocery_data[current_user.id].setdefault(new_category, []).grocery_listend(item)
        else:
            grocery_data[current_user.id][category].grocery_listend(item)

        save_json(DATA_FILE, grocery_data)
        flash('Item updated successfully!', 'success')

    return redirect(url_for('index'))

# Global variable to store the last deleted data for undo
undo_data = {}

# Global variable to store undo data
undo_data = {}

@grocery_list.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    category = request.form.get('category')
    index = int(request.form.get('index'))

    if category in grocery_data[current_user.id]:
        # Store the deleted item in undo_data
        item = grocery_data[current_user.id][category].pop(index)
        undo_data['item'] = {'category': category, 'item': item}
        save_json(DATA_FILE, grocery_data)
        flash('Item deleted successfully!', 'success')

    return redirect(url_for('index', show_undo='true'))

@grocery_list.route('/delete_category', methods=['POST'])
@login_required
def delete_category():
    category = request.form.get('category')

    if category in grocery_data[current_user.id]:
        # Store the deleted category in undo_data
        undo_data['category'] = {category: grocery_data[current_user.id].pop(category)}
        save_json(DATA_FILE, grocery_data)
        flash('Category deleted successfully!', 'success')

    return redirect(url_for('index', show_undo='true'))

@grocery_list.route('/undo')
@login_required
def undo():
    if 'item' in undo_data:
        category = undo_data['item']['category']
        item = undo_data['item']['item']
        grocery_data[current_user.id].setdefault(category, []).grocery_listend(item)
    elif 'category' in undo_data:
        grocery_data[current_user.id].update(undo_data['category'])

    save_json(DATA_FILE, grocery_data)
    undo_data.clear()
    flash('Undo successful!', 'success')
    return redirect(url_for('index'))


@grocery_list.route('/edit_category', methods=['POST'])
@login_required
def edit_category():
    old_name = request.form.get('old_name')
    new_name = request.form.get('new_name')

    if old_name in grocery_data[current_user.id]:
        grocery_data[current_user.id][new_name] = grocery_data[current_user.id].pop(old_name)
        save_json(DATA_FILE, grocery_data)
        flash('Category updated successfully!', 'success')

    return redirect(url_for('index'))



if __name__ == '__main__':
    grocery_list.run(host='0.0.0.0', port=5000, debug=False)

