from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pandas as pd

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
login_manager = LoginManager(app)
login_manager.login_view='login'

class User(UserMixin):
    def __init__(self, user_id, username, password_hash):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash

# Create an in-memory SQLite database (change the path for a persistent database)
DATABASE = 'database.db'
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()

def create_tables():
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bhk INTEGER NOT NULL,
            rent REAL NOT NULL,
            size INTEGER NOT NULL,
            floor TEXT NOT NULL,
            area_type TEXT NOT NULL,
            area_locality TEXT NOT NULL,
            city TEXT NOT NULL,
            furnishing_status TEXT NOT NULL,
            tenant_preferred TEXT NOT NULL,
            bathroom INTEGER NOT NULL,
            point_of_contact TEXT NOT NULL
        )
    ''')
    conn.commit()

create_tables()


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    result = cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if result:
        return User(result[0], result[1], result[2])
    return None

def load_data():
    data = pd.read_csv('rent.csv')
    data.columns = [col.strip() for col in data.columns]

    for _, row in data.iterrows():
        cursor.execute('''
            INSERT INTO properties (
                bhk, rent, size, floor, area_type, area_locality, city,
                furnishing_status, tenant_preferred, bathroom, point_of_contact
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row['BHK'], row['Rent'], row['Size'], row['Floor'],
            row['Area Type'], row['Area Locality'], row['City'],
            row['Furnishing Status'], row['Tenant Preferred'],
            row['Bathroom'], row['Point of Contact']
        ))

    conn.commit()

load_data()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Access rows by column name
    return g.db

@app.teardown_appcontext
def close_db(error):
    if 'db' in g:
        g.db.close()


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        search_term = request.form.get('search_term', '')
        properties = get_db().execute('''
            SELECT * FROM properties
            WHERE area_locality LIKE ? OR city LIKE ? OR furnishing_status LIKE ? OR tenant_preferred LIKE ?
        ''', (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%")).fetchall()
    else:
        properties = get_db().execute('SELECT * FROM properties LIMIT 4').fetchall()

    return render_template('index.html', properties=properties)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Query user from the SQLite database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        result = cursor.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if result and check_password_hash(result[2], password):
            user = User(result[0], result[1], result[2])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        
        # Insert new user into the users table
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/rent/<int:property_id>', methods=['GET', 'POST'])
@login_required
def rent(property_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    property =  cursor.execute('SELECT * FROM properties WHERE id = ?', (property_id,)).fetchone()
    
    if request.method == 'POST':
        flash('Property rented successfully!', 'success')
        return redirect(url_for('thank_you'))
    return render_template('rent.html', property=property)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')

if __name__ == '__main__':
    app.run(debug=True)