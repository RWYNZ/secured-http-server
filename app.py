from flask import Flask, request, render_template, redirect, url_for, session
import os
import sqlite3
import hashlib


app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db():
    conn = sqlite3.connect('database.db')
    return conn

def setup_database():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(''' 
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

setup_database()

@app.route('/')
def index():
    return render_template('index.html')

# Sign Up Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username and password:
            # Generate a salt
            salt = os.urandom(8).hex()
            
            # Store username, plain password, and salt in the database
            conn = get_db()
            cur = conn.cursor()
            cur.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', 
                        (username, password, salt))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        else:
            return "Error: Both username and password are required.", 400
    
    return render_template('signup.html')

# Login Route - Step 1: Username
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        
        if username:
            # Check if the username exists
            conn = get_db()
            cur = conn.cursor()
            cur.execute('SELECT salt FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            conn.close()
            
            if user:
                # Generate a challenge and store it in the session
                challenge = os.urandom(8).hex()
                session['username'] = username
                session['salt'] = user[0]
                session['challenge'] = challenge
                
                # Go to the next step of the login process
                return redirect(url_for('login_password'))
            else:
                return "Error: Username not found.", 400
        else:
            return "Error: Username is required.", 400
    
    return render_template('login.html')

# Login Route - Step 2: Password and Hash
@app.route('/login/password', methods=['GET', 'POST'])
def login_password():
    if request.method == 'POST':
        client_final_hash = request.form.get('client_final_hash')
        client_challenge = request.form.get('challenge')
        
        # Debugging: Print received values
        print("Received client_final_hash:", client_final_hash)
        print("Received client_challenge:", client_challenge)
        
        if not client_final_hash or not client_challenge:
            return "Error: Hash and challenge are required.", 400
        
        # Retrieve salt and username from session
        salt = session.get('salt')
        username = session.get('username')
        
        if not (client_challenge and salt and username):
            return "Error: Session expired. Please try again.", 400
        
        # Retrieve the stored password for comparison
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT password FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()
        
        if not user:
            return "Error: User not found.", 400
        
        stored_password = user[0]
        
        # Server-side hash calculation
        # Step 1: Hash(stored_password + salt)
        hashpw = hashlib.sha256((stored_password + salt).encode()).hexdigest()
        
        # Log intermediate values
        print("Stored Password (plain text):", stored_password)
        print("Salt:", salt)
        print("Challenge:", client_challenge)
        print("Intermediate Hash (stored_password + salt):", hashpw)
        
        # Step 2: Hash(hashpw + challenge)
        server_final_hash = hashlib.sha256((hashpw + client_challenge).encode()).hexdigest()
        
        # Log final hash
        print("Server Final Hash (hashpw + challenge):", server_final_hash)
        
        # Compare client final hash with server final hash
        if client_final_hash == server_final_hash:
            return "Login successful!"
        else:
            return "Login failed! Invalid credentials."
    
    # Render the form with salt and challenge values
    salt = session.get('salt')
    challenge = session.get('challenge')
    return render_template('login_password.html', salt=salt, challenge=challenge)



if __name__ == '__main__':
    app.run(debug=True)
