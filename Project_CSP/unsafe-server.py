import sqlite3
import rsa
import socket


# The IP Address of the server. We will be using localhost IP Address as the socket's IP Address.
server_address = '127.0.0.1'
# The port we will be using for the socket.
port = 5000
# Database file path
db_file = 'credentials.db'

# Create a new SQLite database or connect to an existing one
conn = sqlite3.connect(db_file)
c = conn.cursor()

# Check if the table 'user_service' already exists in the database
c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_service';")
if c.fetchone() is None:
    # Create a new table for storing email and password
    c.execute('''
        CREATE TABLE user_service (
            service PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    print(f"New table 'user_service' created in {db_file}")
else:
    print(f"Table 'user_service' already exists in {db_file}")

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
    client.close()
server.close()
conn.close()
