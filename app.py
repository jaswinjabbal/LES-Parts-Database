from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
import os
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder

import logging
logging.basicConfig(level=logging.DEBUG)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from utils.models import User 
from werkzeug.security import check_password_hash, generate_password_hash

#INTEGRATION
from utils.query_helpers_api import filter_parts, sort_parts, tag_part, add_part, update_part, delete_part

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
#---------let's keep this thing running!--------#
@app.route('/ping')
def ping():
    return "pong", 200

#------------------SSH SETUP------------------#
tunnel = SSHTunnelForwarder(
        ssh_address_or_host=(os.getenv("SSH_HOST"), int(os.getenv("SSH_PORT"))),
        ssh_username=os.getenv("DB_USER"),
        ssh_password=os.getenv("DB_PASS"),
        remote_bind_address=('127.0.0.1', int(os.getenv("DB_PORT"))),
        local_bind_address=('127.0.0.1', int(os.getenv("LOCAL_PORT")))
    )
tunnel.start()

def create_db_connection():
    return mysql.connector.connect(
        host='127.0.0.1',
        port=int(os.getenv("LOCAL_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
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
        user_type = request.form['user_type']  # VERIFY WITH DB
        hashed_pw = generate_password_hash(password)

        conn = create_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, user_type) VALUES (%s, %s, %s)",
                (username, hashed_pw, user_type)
            )
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
        
        conn = create_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, user_type FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cleanup(cursor, conn)

        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1], user_data[2])
            login_user(user)
            session['user_type'] = user_data[3]  #CHECKS 3RD COLUMN
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
#----------------ADMIN ONLY----------------#
@app.route('/admin')
@login_required
def admin():
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, user_type FROM users")
    users = cursor.fetchall()
    cleanup(cursor, conn)

    return render_template('admin.html', users=users, current_user_id=current_user.id)

@app.route('/admin/promote_user/<int:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE users SET user_type = 'admin' WHERE id = %s", (user_id,))
        conn.commit()
        flash('User promoted to admin successfully.')
    except Exception as e:
        flash(f"Error promoting user: {e}")
    finally:
        cleanup(cursor, conn)

    return redirect(url_for('admin'))

@app.route('/admin/demote_user/<int:user_id>', methods=['POST'])
@login_required
def demote_user(user_id):
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE users SET user_type = 'user' WHERE id = %s", (user_id,))
        conn.commit()
        flash('User demoted to user successfully.')
    except Exception as e:
        flash(f"Error demoting user: {e}")
    finally:
        cleanup(cursor, conn)

    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        flash('User deleted successfully.')
    except Exception as e:
        flash(f"Error deleting user: {e}")
    finally:
        cleanup(cursor, conn)

    return redirect(url_for('admin'))

@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        hashed_pw = generate_password_hash(new_password)

        try:
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_pw, user_id))
            conn.commit()
            flash("Password reset successfully.")
            return redirect(url_for('admin'))
        except Exception as e:
            flash(f"Error resetting password: {e}")
        finally:
            cleanup(cursor, conn)

    else:
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cleanup(cursor, conn)

        if not user:
            flash("User not found.")
            return redirect(url_for('admin'))

        return render_template("reset_password.html", user=user)

#--------------------CRUD ROUTES--------------------#
# Home page is a latest paginated dump of parts
@app.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 20
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

#PART LOOKUP/SEARCH
@app.route('/part_lookup', methods=['GET', 'POST'])
@login_required
def part_lookup():
    part = None
    if request.method == 'POST':
        search_term = request.form.get('search_term')

        conn = create_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM electronics_parts
                WHERE `Internal PN` = %s
                   OR `Manufacturer Part Number` = %s
                   OR `Part Description` = %s
                LIMIT 1
            """, (search_term, search_term, search_term))
            part = cursor.fetchone()
        except Exception as e:
            flash(f"Error during lookup: {e}")
        finally:
            cleanup(cursor, conn)

    return render_template('part_lookup.html', part=part)

#FILTER
@app.route('/filter', methods=['GET', 'POST'])
@login_required
def filter():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    selected_category = request.args.get('category')
    selected_value = request.args.get('value')

    data = []
    has_next = False
    total = 0
    columns = [
    "ID",
    "Internal PN",
    "Part Description",
    "Manufacturer",
    "Manufacturer Part Number",
    "Supplier 1",
    "Supplier Part Number 1",
    "Part Category",
    "Updated",
    "Reason",
    "RoHS Compliant",
    "Part Verified",
    "Cost 1pc",
    "Cost 100pc",
    "Cost 1000pc",
    "Tags",
    "Notes",
    "Library Ref",
    "Library Path",
    "Footprint",
    "Footprint Ref",
    "Footprint Path",
    "Datasheet Document",
    "Primary Vendor Stock",
    "Simulation",
    "Value",
    "ComponentLink1URL",
    "ComponentLink1Description",
    "ComponentLink2URL",
    "ComponentLink2Description",
    "Current Inventory",
    "Signal Integrity",
    "Location",
    "Auto Update",
    "Verified By",
    "Parameters",
    "Project List"
    ]

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

    return render_template("filter.html", data=data, columns=columns, selected_category=selected_category, selected_value=selected_value, page=page, has_next=has_next, total=total)

#SORT
@app.route('/sort', methods=['GET', 'POST'])
@login_required
def sort():
    page = request.args.get('page', 1, type=int)
    per_page = 20
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

#TAG
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

#ADD
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

#MANUAL ADD
@app.route('/manual_add', methods=['GET', 'POST'])
@login_required
def manual_add():
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    if request.method == 'POST':
        form_data = {
            'Internal PN': request.form.get('internal_pn'),
            'Part Description': request.form.get('part_description'),
            'Manufacturer': request.form.get('manufacturer'),
            'Manufacturer Part Number': request.form.get('manufacturer_pn'),
            'Supplier 1': request.form.get('supplier_1'),
            'Supplier Part Number 1': request.form.get('supplier_pn_1'),
            'Part Category': request.form.get('part_category'),
            'Updated': request.form.get('updated'),
            'Reason': request.form.get('reason'),
            'RoHS Compliant': request.form.get('rohs_compliant'),
            'Part Verified': request.form.get('part_verified'),
            'Cost 1pc': request.form.get('cost_1pc'),
            'Cost 100pc': request.form.get('cost_100pc'),
            'Cost 1000pc': request.form.get('cost_1000pc'),
            'Tags': request.form.get('tags'),
            'Notes': request.form.get('notes'),
            'Library Ref': request.form.get('library_ref'),
            'Library Path': request.form.get('library_path'),
            'Footprint': request.form.get('footprint'),
            'Footprint Ref': request.form.get('footprint_ref'),
            'Footprint Path': request.form.get('footprint_path')
        }

        conn = create_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO electronics_parts (
                    `Internal PN`, `Part Description`, Manufacturer, `Manufacturer Part Number`,
                    `Supplier 1`, `Supplier Part Number 1`, `Part Category`, Updated, Reason,
                    `RoHS Compliant`, `Part Verified`, `Cost 1pc`, `Cost 100pc`, `Cost 1000pc`,
                    Tags, Notes, `Library Ref`, `Library Path`, Footprint, `Footprint Ref`, `Footprint Path`
                ) VALUES (
                    %(Internal PN)s, %(Part Description)s, %(Manufacturer)s, %(Manufacturer Part Number)s,
                    %(Supplier 1)s, %(Supplier Part Number 1)s, %(Part Category)s, %(Updated)s, %(Reason)s,
                    %(RoHS Compliant)s, %(Part Verified)s, %(Cost 1pc)s, %(Cost 100pc)s, %(Cost 1000pc)s,
                    %(Tags)s, %(Notes)s, %(Library Ref)s, %(Library Path)s, %(Footprint)s,
                    %(Footprint Ref)s, %(Footprint Path)s
                )
            """, form_data)
            conn.commit()
            flash('Part added successfully!')
            return redirect(url_for('manual_add'))
        except Exception as e:
            flash(f"Error adding part: {e}")
        finally:
            cleanup(cursor, conn)

    return render_template('manual_add.html')

#MANUAL EDIT
@app.route('/manual_edit', methods=['GET', 'POST'])
@login_required
def manual_edit_selector():
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        part_id = request.form.get('part_id')
        internal_pn = request.form.get('internal_pn')
        part_description = request.form.get('part_description')

        try:
            if part_id:
                cursor.execute("SELECT ID FROM electronics_parts WHERE ID = %s", (part_id,))
            elif internal_pn:
                cursor.execute("SELECT ID FROM electronics_parts WHERE `Internal PN` = %s", (internal_pn,))
            elif part_description:
                cursor.execute("SELECT ID FROM electronics_parts WHERE `Part Description` = %s", (part_description,))
            else:
                flash("Please fill in at least one field.")
                return redirect(url_for('manual_edit_selector'))

            result = cursor.fetchone()
            if result:
                return redirect(url_for('manual_edit', part_id=result['ID']))
            else:
                flash("Part not found.")

        except Exception as e:
            flash(f"Error finding part: {e}")
        finally:
            cleanup(cursor, conn)

    else:
        cursor.execute("SELECT ID, `Internal PN`, `Part Description` FROM electronics_parts")
        parts = cursor.fetchall()
        cleanup(cursor, conn)

        return render_template('manual_edit_selector.html', parts=parts)

#MANUAL EDIT REDIRECT
@app.route('/manual_edit/<int:part_id>', methods=['GET', 'POST'])
@login_required
def manual_edit(part_id):
    if session.get('user_type') != 'admin':
        flash("Access denied: Admins only.")
        return redirect(url_for('index'))

    conn = create_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        updated_data = {
            'Internal PN': request.form.get('internal_pn'),
            'Part Description': request.form.get('part_description'),
            'Manufacturer': request.form.get('manufacturer'),
            'Manufacturer Part Number': request.form.get('manufacturer_pn'),
            'Supplier 1': request.form.get('supplier_1'),
            'Supplier Part Number 1': request.form.get('supplier_pn_1'),
            'Part Category': request.form.get('part_category'),
            'Updated': request.form.get('updated'),
            'Reason': request.form.get('reason'),
            'RoHS Compliant': request.form.get('rohs_compliant'),
            'Part Verified': request.form.get('part_verified'),
            'Cost 1pc': request.form.get('cost_1pc'),
            'Cost 100pc': request.form.get('cost_100pc'),
            'Cost 1000pc': request.form.get('cost_1000pc'),
            'Tags': request.form.get('tags'),
            'Notes': request.form.get('notes'),
            'Library Ref': request.form.get('library_ref'),
            'Library Path': request.form.get('library_path'),
            'Footprint': request.form.get('footprint'),
            'Footprint Ref': request.form.get('footprint_ref'),
            'Footprint Path': request.form.get('footprint_path'),
            'ID': part_id
        }

        try:
            cursor.execute("""
                UPDATE electronics_parts SET
                    `Internal PN` = %(Internal PN)s,
                    `Part Description` = %(Part Description)s,
                    Manufacturer = %(Manufacturer)s,
                    `Manufacturer Part Number` = %(Manufacturer Part Number)s,
                    `Supplier 1` = %(Supplier 1)s,
                    `Supplier Part Number 1` = %(Supplier Part Number 1)s,
                    `Part Category` = %(Part Category)s,
                    Updated = %(Updated)s,
                    Reason = %(Reason)s,
                    `RoHS Compliant` = %(RoHS Compliant)s,
                    `Part Verified` = %(Part Verified)s,
                    `Cost 1pc` = %(Cost 1pc)s,
                    `Cost 100pc` = %(Cost 100pc)s,
                    `Cost 1000pc` = %(Cost 1000pc)s,
                    Tags = %(Tags)s,
                    Notes = %(Notes)s,
                    `Library Ref` = %(Library Ref)s,
                    `Library Path` = %(Library Path)s,
                    Footprint = %(Footprint)s,
                    `Footprint Ref` = %(Footprint Ref)s,
                    `Footprint Path` = %(Footprint Path)s
                WHERE ID = %(ID)s
            """, updated_data)
            conn.commit()
            flash("Part updated successfully.")
            return redirect(url_for('manual_edit', part_id=part_id))
        except Exception as e:
            flash(f"Error updating part: {e}")
        finally:
            cleanup(cursor, conn)

    else:
        cursor.execute("SELECT * FROM electronics_parts WHERE ID = %s", (part_id,))
        part = cursor.fetchone()
        cleanup(cursor, conn)

        if not part:
            flash("Part not found.")
            return redirect(url_for('index'))

        return render_template("manual_edit.html", part=part)


#UPDATE
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

#DELETE
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

#------------------RUN APP------------------#
if __name__ == '__main__':
    app.run(debug=True)
