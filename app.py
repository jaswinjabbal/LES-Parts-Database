from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import mysql.connector
import os
import json
from sshtunnel import SSHTunnelForwarder
import random
import string
import logging
logging.basicConfig(level=logging.DEBUG)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from utils.models import User 
from werkzeug.security import check_password_hash, generate_password_hash

#INTEGRATION
from utils.query_helpers_api import filter_parts, sort_parts, tag_part, add_part, update_part, delete_part


app = Flask(__name__)
app.secret_key = 'your_secret_key_here_1234567890'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


tunnel = SSHTunnelForwarder(
        ssh_address_or_host=('lusherengineeringservices.com', 22),
        ssh_username='ecen404team45',
        ssh_password='ecen404$592H#!cx',
        remote_bind_address=('127.0.0.1', 3306),
        local_bind_address=('127.0.0.1', 3307)
    )
tunnel.start()

def create_db_connection():
    return mysql.connector.connect(
        host='127.0.0.1',
        port=3307,
        user='ecen404team45',
        password='ecen404$592H#!cx',
        database='lusher engineering parts database'
    )

def cleanup(cursor, conn):
    if cursor: cursor.close()
    if conn: conn.close()

#------------------USERS TABLE------------------#
@login_manager.user_loader
def load_user(user_id):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    cleanup(cursor, conn)
    if row:
        return User(id=row[0], username=row[1], password_hash=row[2])
    return None
#--------------------AUTH ROUTES-----------------#
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        conn = create_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_pw))
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username already exists. Choose another.')
        finally:
            cleanup(cursor, conn)
    return render_template('register.html')

from flask import session

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        selected_user_type = request.form['user_type']  # Dropdown selection

        # Authenticate with DB
        conn = create_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cleanup(cursor, conn)

        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user)

            # Use dropdown selection (demo purpose) instead of DB user_type
            session['user_type'] = selected_user_type  # 'admin' or 'user' from dropdown
            return redirect(url_for('index'))

        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#----------------------- CRUD ROUTES--------------------#
#home page is currently a paginated dump of parts
@app.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    conn = create_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as total FROM electronics_parts")
    total_parts = cursor.fetchone()['total']

    cursor.execute("SELECT * FROM electronics_parts LIMIT %s OFFSET %s", (per_page, offset))
    data = cursor.fetchall()

    has_next = (offset + per_page) < total_parts

    cleanup(cursor, conn)
    return render_template('index.html', data=data, page=page, has_next=has_next)

#filter works
@app.route('/filter', methods=['GET', 'POST'])
@login_required
def filter():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    selected_category = request.args.get('category')
    selected_value = request.args.get('value')

    data = []
    has_next = False
    columns = ['Manufacturer', 'Supplier 1', 'Part Category', 'RoHS Compliant']  # Or fetch dynamically if needed

    if request.method == 'POST':
        selected_category = request.form['category']
        selected_value = request.form['value']
        return redirect(url_for('filter', page=1, category=selected_category, value=selected_value))

    if selected_category and selected_value:
        try:
            all_data = filter_parts(selected_category, selected_value)
            total = len(all_data)
            data = all_data[offset:offset + per_page]
            has_next = offset + per_page < total
        except Exception as e:
            flash(f"Error during filtering: {e}")

    return render_template("filter.html", data=data, columns=columns, selected_category=selected_category, selected_value=selected_value, page=page, has_next=has_next)

#sort works
@app.route('/sort', methods=['GET', 'POST'])
@login_required
def sort():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    category = request.args.get('category')
    selected_category = category
    data = []
    total = 0
    has_next = False

    if request.method == 'POST':
        category = request.form.get('category')
        return redirect(url_for('sort', page=1, category=category))

    if category:
        try:
            all_data = sort_parts(category)
            total = len(all_data)
            data = all_data[offset:offset + per_page]
            has_next = (offset + per_page) < total
        except Exception as e:
            flash(f"Error during sorting: {e}")

    return render_template('sort.html', data=data, page=page, has_next=has_next, selected_category=selected_category, columns=["Manufacturer", "Supplier", "Part_Category", "Cost_1pc", "Stock"])

#need to test tag
@app.route('/tag', methods=['GET', 'POST'])
@login_required
def tag():
    if request.method == 'POST':
        part_number = request.form['part_number']
        tag_value = request.form['tag']
        try:
            result = tag_part(part_number, tag_value)
            flash(result if isinstance(result, str) else result.get('message', 'Tag updated successfully!'))
        except Exception as e:
            flash(f"Error during tagging: {e}")
        return redirect(url_for('tag'))
    return render_template('tag_part.html')

#add works
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        part_number = request.form['part_number']

        try:
            result = add_part(part_number)

            print("[DEBUG] Result from API:", result)

            if isinstance(result, dict) and result.get('success'):
                flash(result)
            else:
                flash(f"API Says: {result}")
        except Exception as e:
            flash(f"Error during API call: {e}")
        return redirect(url_for('add'))
    return render_template('add_part.html')

#update works
@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    if request.method == 'POST':
        lower = request.form['lower']
        upper = request.form['upper']

        try:
            result = update_part(lower, upper)

            # Display success message if API returns any
            flash(f"Update triggered via API. Response: {result}")
        except Exception as e:
            flash(f"Error during API call: {e}")

        return redirect(url_for('update'))

    return render_template('update.html')

#need to test delete
@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == 'POST':
        category = request.form['category']
        value = request.form['value']
        try:
            result = delete_part(category, value)
            flash(result if isinstance(result, str) else result.get('message', 'Part(s) deleted successfully!'))
        except Exception as e:
            flash(f"Error during deletion: {e}")
        return redirect(url_for('delete'))
    return render_template('delete.html')

#-----------------------RUN APP--------------------#
if __name__ == '__main__':
    app.run(debug=True)
