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

# Login user
def login_user(username, password):
    cur.execute("SELECT username FROM users WHERE username = ? AND password = ?", (username, password))
    if cur.fetchone() is not None:
        return True
    return False

# Function to add a new site with password
def add_new_site(username, site_name, password):
    try:
        cur.execute("INSERT INTO sites (username, site_name, password) VALUES (?, ?, ?)", (username, site_name, password))
        conn.commit()
        print(f"New site '{site_name}' added for user '{username}'")
        return True
    except sqlite3.IntegrityError:
        print(f"Site '{site_name}' already exists for user '{username}'")
        return False
    except Exception as e:
        print(f"Error adding new site: {e}")
        return False

# Function to retrieve password for a specific site
def retrieve_password(username, site_name):
    try:
        cur.execute("SELECT password FROM sites WHERE username = ? AND site_name = ?", (username, site_name))
        result = cur.fetchone()
        if result:
            password = result[0]
            print(f"Password retrieved for site '{site_name}' of user '{username}'")
            return password
        else:
            print(f"Password not found for site '{site_name}' of user '{username}'")
            return None
    except Exception as e:
        print(f"Error retrieving password: {e}")
        return None


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(1)

    print("Server listening on port 65432...")

    while True:
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

            elif action == 'login':
                username, password = args.split('\n')
                print("LOGGING IN USER...")
                print(f"Username: {username}")
                print(f"Password: {password}")

                # Login the user and send response to client
                if login_user(username, password):
                    client_socket.send("1".encode())
                else:
                    client_socket.send("0".encode())

            elif action == 'retrieve':
                username, site_name = args.split(',')
                print("RETRIEVING PASSWORD...")
                print(f"Username: {username}")
                print(f"Site Name: {site_name}")

                # Implement logic to retrieve password for the given site
                password = retrieve_password(username, site_name)
                if password:
                    client_socket.send(password.encode())
                else:
                    client_socket.send("Password not found.".encode())

            elif action == 'add':
                username, new_site_name, new_password = args.split(',')
                print("ADDING NEW SITE...")
                print(f"Username: {username}")
                print(f"New Site Name: {new_site_name}")
                print(f"New Password: {new_password}")

                # Implement logic to add a new site with the provided password
                if add_new_site(username, new_site_name, new_password):
                    client_socket.send("1".encode())  # New site added successfully
                else:
                    client_socket.send("0".encode())  # Failed to add new site

        except Exception as e:
            print(f"Error processing client data: {e}")

        finally:
            # Close the client socket
            client_socket.close()

if __name__ == '__main__':
    start_server()


if __name__ == '__main__':
    start_server()
