import sqlite3
import bcrypt
import rsa
import socket

# The IP Address of the server. We will be using localhost IP Address as the socket's IP Address.
server_address = '127.0.0.1'
# The port we will be using for the socket.
port = 5000
# Database file path, which should just be the current folder
db_file = "credentials.db"

# Create a new SQLite database or connect to an existing one
conn = sqlite3.connect(db_file)
c = conn.cursor()

# Check if the table 'users' already exists in the database
c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
if c.fetchone() is None:
    # Create a new table for storing email and password
    c.execute('''
        CREATE TABLE users (
            email TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
    ''')
    print(f"New table 'users' created in {db_file}")
else:
    print(f"Table 'users' already exists in {db_file}")

# Assume 'public_key' and 'private_key' are the public and private keys
(public_key, private_key) = rsa.newkeys(2048)

# Save the public key to a file
with open("server_public_key.pem", "wb") as key_file:
    key_file.write(public_key.save_pkcs1())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((server_address, port))
server.listen(1)
print("Server is listening...")

while True:
    client, address = server.accept()
    print(f"Connection established with {address}")

    # Receive encrypted credentials from the client
    encrypted_credentials = client.recv(1024)
    action, credentials = encrypted_credentials.split(b'\n', 1)  # split using bytes, not string
    action = action.decode()  # decode action to string
    if action == "exit":
        print("Client requested to exit.")
        client.close()
        break
    credentials = rsa.decrypt(credentials, private_key).decode()

    # Extract email and password from credentials
    email, password_hash = credentials.split('\n')
    print(f"Received credentials: {email}, {password_hash}")

    # Query the database for the email
    if action == "signup":
        # check if email is already in the database
        c.execute("SELECT email FROM users WHERE email = ?", (email,))
        if c.fetchone() is not None:
            print("Signup Failed! Email already exists.")
            client.send("0".encode())
            client.close()
            continue
        # If the action is signup, store the new credentials
        hashed_password = bcrypt.hashpw(password_hash.encode(), bcrypt.gensalt())
        c.execute("INSERT INTO users VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        print(f"New credentials stored for email: {email}")
        client.send("1".encode())
        # print whats in the database
        c.execute("SELECT * FROM users")
        print(c.fetchall())

    elif action == "login":
        # If the action is login, check the credentials
        c.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        print("row", row)
        if row is not None:
            # If the email is in the database, check if the password is correct
            if bcrypt.checkpw(password_hash.encode(), row[0]):
                print("Login Successful!")
                client.send("1".encode())
            else:
                print("Login Failed! Incorrect password.")
                client.send("0".encode())
        else:
            print("Login Failed! Email not found.")
            client.send("0".encode())
server.close()
conn.close()
