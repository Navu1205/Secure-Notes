import sqlite3
import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')

DATABASE = 'notes.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        validate_csrf_token()
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not email or not password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('signup.html')
        
        conn = get_db()
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            flash('Email already registered. Please login.', 'error')
            conn.close()
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password)
        conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        validate_csrf_token()
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('login.html')
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    notes = conn.execute(
        'SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    
    return render_template('dashboard.html', notes=notes)

@app.route('/create_note', methods=['POST'])
@login_required
def create_note():
    validate_csrf_token()
    title = request.form.get('title')
    content = request.form.get('content')
    
    if not title or not content:
        flash('Title and content are required.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    conn.execute(
        'INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)',
        (session['user_id'], title, content)
    )
    conn.commit()
    conn.close()
    
    flash('Note created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    validate_csrf_token()
    conn = get_db()
    note = conn.execute('SELECT * FROM notes WHERE id = ? AND user_id = ?', (note_id, session['user_id'])).fetchone()
    
    if note:
        conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
        conn.commit()
        flash('Note deleted successfully!', 'success')
    else:
        flash('Note not found or unauthorized.', 'error')
    
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/update_note/<int:note_id>', methods=['POST'])
@login_required
def update_note(note_id):
    validate_csrf_token()
    title = request.form.get('title')
    content = request.form.get('content')

    if not title or not content:
        flash('Title and content are required.', 'error')
        return redirect(url_for('dashboard'))

    conn = get_db()
    # Ensure the note belongs to the current user
    note = conn.execute(
        'SELECT * FROM notes WHERE id = ? AND user_id = ?',
        (note_id, session['user_id'])
    ).fetchone()

    if not note:
        conn.close()
        flash('Note not found or unauthorized.', 'error')
        return redirect(url_for('dashboard'))

    conn.execute(
        'UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?',
        (title, content, note_id, session['user_id'])
    )
    conn.commit()
    conn.close()

    flash('Note updated successfully!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
