import socket
import sqlite3

DATABASE_NAME = 'password_manager.db'

# Create a new SQLite database or connect to an existing one
conn = sqlite3.connect(DATABASE_NAME)
cur = conn.cursor()

# Check if the table 'users' already exists in the database
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
if cur.fetchone() is None:
    # Create a new table for storing email and password
    cur.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
    ''')
    print(f"New table 'users' created in {DATABASE_NAME}")
else:
    print(f"Table 'users' exists in {DATABASE_NAME}")

# Register new user
def register_user(username, password):
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cur.fetchone() is not None:
        print("THE USER ALREADY EXISTS")
        return False

    cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    return True

def server_stuff(server_socket):
    # Accept incoming connection and get client socket
        client_socket, addr = server_socket.accept()
        print(f"Connection established from {addr}")

        # Receive data from the client
        data = client_socket.recv(1024).decode()
        action, args = data.split(',', 1)  # Split into action and arguments

        if action == 'register':
            username, password = args.split('\n')
            print("REGISTERING USER...")
            print(f"Username: {username}")
            print(f"Password: {password}")
            # Register the user and send response to client
            if register_user(username, password):
                client_socket.send("1".encode())  # User registered successfully

            else:
                client_socket.send("0".encode())  # User registration failed (username already exists)
                client_socket.close()
                server_stuff(server_socket)
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(5)
    print("Server listening on port 65432...")
    server_stuff(server_socket)
      # Close the connection after processing the request


if __name__ == '__main__':
    start_server()
