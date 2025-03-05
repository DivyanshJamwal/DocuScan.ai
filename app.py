from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import sqlite3
import os
import hashlib
from datetime import datetime, timedelta
import logging
import requests
from collections import Counter
import json

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'

# Google Gemini API Key (replace with your key or set via environment)
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'AIzaSyAtKmaTAuQJ8gSVyDK7MHCMJbyd4PFE_lk')

# Ensure folders exist
for folder in [UPLOAD_FOLDER, LOG_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Setup logging
logging.basicConfig(filename=os.path.join(LOG_FOLDER, 'activity.log'), 
                    level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role INTEGER DEFAULT 0,
        credits INTEGER DEFAULT 20,
        scan_count INTEGER DEFAULT 0,
        last_reset TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS credit_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        requested_credits INTEGER,
        status TEXT DEFAULT 'pending',
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT NOT NULL,
        content TEXT NOT NULL,
        upload_date TEXT DEFAULT CURRENT_TIMESTAMP,
        embedding TEXT,  -- Store Gemini embeddings as JSON
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    admin_password = hash_password('admin123')
    try:
        c.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, 1)', ('admin', admin_password))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_auth():
    return 'user_id' in session

def require_role(role):
    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if not check_auth():
                flash('Please log in first.', 'error')
                return redirect(url_for('login_page'))
            if session.get('role') != role:
                flash('Unauthorized access.', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        wrapped_function.__name__ = f.__name__
        return wrapped_function
    return decorator

def reset_credits_if_needed(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT last_reset FROM users WHERE id = ?', (user_id,))
    last_reset = c.fetchone()[0]
    last_reset_date = datetime.strptime(last_reset, '%Y-%m-%d %H:%M:%S')
    now = datetime.now()
    if last_reset_date.date() < now.date():
        c.execute('UPDATE users SET credits = 20, last_reset = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
        conn.commit()
        logging.info(f"Credits reset to 20 for user_id {user_id}")
    conn.close()

def get_gemini_embedding(text):
    try:
        # Note: Gemini API specifics may vary; this assumes a REST endpoint similar to others
        # Adjust URL and params based on latest Gemini API docs
        url = 'https://generativelanguage.googleapis.com/v1beta/models/embedding-001:embedContent'
        headers = {'Content-Type': 'application/json'}
        params = {'key': GEMINI_API_KEY}
        data = {
            'content': {'parts': [{'text': text}]},
            'task_type': 'SEMANTIC_SIMILARITY'
        }
        response = requests.post(url, headers=headers, params=params, json=data)
        response.raise_for_status()
        embedding = response.json()['embedding']['values']
        return embedding
    except Exception as e:
        logging.error(f"Gemini embedding failed: {e}")
        return None

def cosine_similarity(vec1, vec2):
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = sum(a * a for a in vec1) ** 0.5
    norm2 = sum(b * b for b in vec2) ** 0.5
    return (dot_product / (norm1 * norm2)) * 100 if norm1 * norm2 > 0 else 0

def get_common_topics():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT content FROM documents')
    all_docs = c.fetchall()
    conn.close()
    all_words = Counter()
    for doc in all_docs:
        all_words.update(doc[0].lower().split())
    return [word for word, count in all_words.most_common(5)]

# Routes
@app.route('/')
def home():
    if check_auth():
        if session['role'] == 1:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('profile'))
    return render_template('index.html')

@app.route('/auth/register', methods=['GET'])
def register_page():
    if check_auth():
        return redirect(url_for('profile'))
    return render_template('auth/register.html')

@app.route('/auth/register', methods=['POST'])
def register():
    username = request.form['username']
    password = hash_password(request.form['password'])
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password))
        conn.commit()
        flash('Registration successful! Please log in.', 'success')
        logging.info(f"User registered: {username}")
        return redirect(url_for('login_page'))
    except sqlite3.IntegrityError:
        flash('Username already taken.', 'error')
        return redirect(url_for('register_page'))
    finally:
        conn.close()

@app.route('/auth/login', methods=['GET'])
def login_page():
    if check_auth():
        return redirect(url_for('profile'))
    return render_template('auth/login.html')

@app.route('/auth/login', methods=['POST'])
def login():
    username = request.form['username']
    password = hash_password(request.form['password'])
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, password_hash, role FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if user and user[1] == password:
        session['user_id'] = user[0]
        session['role'] = user[2]
        reset_credits_if_needed(user[0])
        flash('Logged in successfully!', 'success')
        logging.info(f"User logged in: {username}")
        if user[2] == 1:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('profile'))
    flash('Invalid username or password.', 'error')
    return redirect(url_for('login_page'))

@app.route('/user/profile')
@require_role(0)
def profile():
    reset_credits_if_needed(session['user_id'])
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT username, credits, scan_count FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()
    return render_template('user/profile.html', username=user[0], credits=user[1], scan_count=user[2])

@app.route('/admin/dashboard')
@require_role(1)
def admin_dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users WHERE role = 0')
    user_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM credit_requests WHERE status = "pending"')
    pending_requests = c.fetchone()[0]
    c.execute('''SELECT u.username, COUNT(d.id) 
                 FROM users u 
                 LEFT JOIN documents d ON u.id = d.user_id 
                 WHERE u.role = 0 AND d.upload_date > ? 
                 GROUP BY u.id, u.username''', 
              ((datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S'),))
    scans_per_user = c.fetchall()
    c.execute('SELECT username, scan_count FROM users WHERE role = 0 ORDER BY scan_count DESC LIMIT 5')
    top_users = c.fetchall()
    c.execute('SELECT SUM(requested_credits) FROM credit_requests WHERE status = "approved"')
    total_credits_approved = c.fetchone()[0] or 0
    conn.close()
    common_topics = get_common_topics()
    return render_template('admin/dashboard.html', 
                          user_count=user_count, 
                          pending_requests=pending_requests,
                          scans_per_user=scans_per_user,
                          common_topics=common_topics,
                          top_users=top_users,
                          total_credits_approved=total_credits_approved)

@app.route('/user/request_credits', methods=['GET'])
@require_role(0)
def request_credits_page():
    return render_template('user/request_credits.html')

@app.route('/user/request_credits', methods=['POST'])
@require_role(0)
def request_credits():
    requested_credits = request.form['credits']
    if not requested_credits.isdigit() or int(requested_credits) <= 0:
        flash('Please enter a valid number of credits.', 'error')
        return redirect(url_for('request_credits_page'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO credit_requests (user_id, requested_credits) VALUES (?, ?)', 
              (session['user_id'], int(requested_credits)))
    conn.commit()
    conn.close()
    flash('Credit request submitted successfully!', 'success')
    logging.info(f"User {session['user_id']} requested {requested_credits} credits")
    return redirect(url_for('profile'))

@app.route('/admin/manage_credits', methods=['GET'])
@require_role(1)
def manage_credits():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT cr.id, u.username, cr.requested_credits, cr.timestamp 
                 FROM credit_requests cr 
                 JOIN users u ON cr.user_id = u.id 
                 WHERE cr.status = 'pending' 
                 ORDER BY cr.timestamp''')
    requests = c.fetchall()
    conn.close()
    return render_template('admin/manage_credits.html', requests=requests)

@app.route('/admin/manage_credits', methods=['POST'])
@require_role(1)
def manage_credits_action():
    request_id = request.form['request_id']
    action = request.form['action']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if action == 'approve':
        c.execute('SELECT user_id, requested_credits FROM credit_requests WHERE id = ?', (request_id,))
        req = c.fetchone()
        if req:
            user_id, credits = req
            c.execute('UPDATE users SET credits = credits + ? WHERE id = ?', (credits, user_id))
            c.execute('UPDATE credit_requests SET status = "approved" WHERE id = ?', (request_id,))
            flash(f'Approved {credits} credits for user.', 'success')
            logging.info(f"Admin approved {credits} credits for user_id {user_id}")
    elif action == 'deny':
        c.execute('UPDATE credit_requests SET status = "denied" WHERE id = ?', (request_id,))
        flash('Credit request denied.', 'success')
        logging.info(f"Admin denied credit request {request_id}")
    conn.commit()
    conn.close()
    return redirect(url_for('manage_credits'))

@app.route('/user/scan', methods=['GET'])
@require_role(0)
def scan_page():
    reset_credits_if_needed(session['user_id'])
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],))
    credits = c.fetchone()[0]
    conn.close()
    return render_template('user/scan.html', credits=credits)

@app.route('/user/scan', methods=['POST'])
@require_role(0)
def scan_upload():
    reset_credits_if_needed(session['user_id'])
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],))
    credits = c.fetchone()[0]
    if credits < 1:
        flash('Insufficient credits. Request more or wait for daily reset.', 'error')
        conn.close()
        return redirect(url_for('scan_page'))
    if 'document' not in request.files:
        flash('No file uploaded.', 'error')
        conn.close()
        return redirect(url_for('scan_page'))
    file = request.files['document']
    if file.filename == '':
        flash('No file selected.', 'error')
        conn.close()
        return redirect(url_for('scan_page'))
    if file and file.filename.endswith('.txt'):
        content = file.read().decode('utf-8')
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        embedding = get_gemini_embedding(content)
        embedding_json = json.dumps(embedding) if embedding else None
        c.execute('INSERT INTO documents (user_id, filename, content, embedding) VALUES (?, ?, ?, ?)', 
                  (session['user_id'], filename, content, embedding_json))
        c.execute('UPDATE users SET credits = credits - 1, scan_count = scan_count + 1 WHERE id = ?', 
                  (session['user_id'],))
        c.execute('SELECT id, filename, content, embedding FROM documents WHERE user_id != ?', (session['user_id'],))
        all_docs = c.fetchall()
        matches = []
        if embedding:
            for doc in all_docs:
                doc_id, doc_filename, doc_content, doc_embedding = doc
                if doc_embedding:
                    similarity = cosine_similarity(embedding, json.loads(doc_embedding))
                    if similarity > 20:
                        matches.append({'id': doc_id, 'filename': doc_filename, 'similarity': similarity})
                else:
                    similarity = calculate_similarity(content, doc_content)
                    if similarity > 20:
                        matches.append({'id': doc_id, 'filename': doc_filename, 'similarity': similarity})
        else:
            for doc in all_docs:
                doc_id, doc_filename, doc_content, _ = doc
                similarity = calculate_similarity(content, doc_content)
                if similarity > 20:
                    matches.append({'id': doc_id, 'filename': doc_filename, 'similarity': similarity})
        matches.sort(key=lambda x: x['similarity'], reverse=True)
        conn.commit()
        conn.close()
        flash('Document uploaded and scanned successfully!', 'success')
        logging.info(f"User {session['user_id']} scanned {filename}")
        return render_template('user/matches.html', matches=matches[:5])
    else:
        flash('Only .txt files are supported.', 'error')
        conn.close()
    return redirect(url_for('scan_page'))

@app.route('/admin/scan', methods=['GET'])
@require_role(1)
def admin_scan_page():
    return render_template('admin/scan.html')

@app.route('/admin/scan', methods=['POST'])
@require_role(1)
def admin_scan_upload():
    if 'document' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('admin_scan_page'))
    file = request.files['document']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('admin_scan_page'))
    if file and file.filename.endswith('.txt'):
        content = file.read().decode('utf-8')
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        embedding = get_gemini_embedding(content)
        embedding_json = json.dumps(embedding) if embedding else None
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO documents (user_id, filename, content, embedding) VALUES (?, ?, ?, ?)', 
                  (session['user_id'], filename, content, embedding_json))
        c.execute('UPDATE users SET scan_count = scan_count + 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        flash('Document uploaded successfully! (No matching for admins)', 'success')
        logging.info(f"Admin {session['user_id']} uploaded {filename}")
        return redirect(url_for('admin_scan_page'))
    else:
        flash('Only .txt files are supported.', 'error')
        return redirect(url_for('admin_scan_page'))

@app.route('/user/export_history')
@require_role(0)
def export_history():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT filename, upload_date FROM documents WHERE user_id = ?', (session['user_id'],))
    history = c.fetchall()
    conn.close()
    export_file = f"scan_history_{session['user_id']}.txt"
    with open(export_file, 'w') as f:
        f.write("Scan History\n")
        f.write("------------\n")
        for filename, date in history:
            f.write(f"File: {filename}, Uploaded: {date}\n")
    logging.info(f"User {session['user_id']} exported scan history")
    return send_file(export_file, as_attachment=True)

@app.route('/logout')
def logout():
    username = session.get('user_id', 'Unknown')
    session.pop('user_id', None)
    session.pop('role', None)
    flash('Logged out successfully!', 'success')
    logging.info(f"User {username} logged out")
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)