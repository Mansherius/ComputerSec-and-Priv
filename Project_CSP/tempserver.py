# server.py
import socket
import sqlite3

DATABASE_NAME = 'password_manager.db'

# Initialize database and tables
def initialize_database():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Create passwords table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            site_name TEXT,
            password TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

# Store password in database
def store_password(username, site_name, password):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Get user ID
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = cursor.fetchone()[0]

    # Store password
    cursor.execute('''
        INSERT INTO passwords (user_id, site_name, password)
        VALUES (?, ?, ?)
    ''', (user_id, site_name, password))

    conn.commit()
    conn.close()

# Retrieve password from database
def retrieve_password(username, site_name):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Get user ID
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user_id = cursor.fetchone()[0]

    # Retrieve password
    cursor.execute('''
        SELECT password FROM passwords
        WHERE user_id = ? AND site_name = ?
    ''', (user_id, site_name))

    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    else:
        return None

# User authentication
def authenticate_user(username, password):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    conn.close()

    if result and result[0] == password:
        return True
    else:
        return False

# Register new user
def register_user(username, password):
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # User already exists (username is not unique)
        conn.close()
        return False

def start_server():
    initialize_database()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(1)

    print("Server listening on port 65432...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection established from {addr}")

        data = conn.recv(1024).decode()
        action, *args = data.split(',')

        if action == 'register':
            username, password = args
            if register_user(username, password):
                conn.sendall(b'1')  # User registered successfully
            else:
                conn.sendall(b'0')  # User registration failed (username already exists)
        elif action == 'login':
            username, password = args
            if authenticate_user(username, password):
                conn.sendall(b'1')  # Authentication successful
            else:
                conn.sendall(b'0')  # Authentication failed
        elif action == 'store':
            username, site_name, password = args
            store_password(username, site_name, password)
            conn.sendall(b'Successfully stored password.')
        elif action == 'retrieve':
            username, site_name = args
            password = retrieve_password(username, site_name)
            if password:
                conn.sendall(password.encode())
            else:
                conn.sendall(b'Password not found.')

        conn.close()

if __name__ == '__main__':
    start_server()
