import sqlite3
import bcrypt
import rsa
import socket

# The IP Address of the server. We will be using localhost IP Address as the socket's IP Address.
server_address = '127.0.0.1'
# The port we will be using for the socket.
port = 65432
# Database file path, which should just be the current folder
cred_db = "credentials.db"

# Create a new SQLite database or connect to an existing one
conn = sqlite3.connect(cred_db)
cred_table = conn.cursor()

# Check if the table 'users' already exists in the database
cred_table.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
if cred_table.fetchone() is None:
    # Create a new table for storing email and password
    cred_table.execute('''
        CREATE TABLE users (
            email TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
    ''')
    print(f"New table 'users' created in {cred_db}")
else:
    print(f"Table 'users' already exists in {cred_db}")

# Assume 'public_key' and 'private_key' are the public and private keys
(public_key_server, private_key_server) = rsa.newkeys(2048)
# get the public key of the client



# Save the public key to a file
with open("server_public_key.pem", "wb") as key_file:
    key_file.write(public_key_server.save_pkcs1())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((server_address, port))
server.listen(1)
print("Server is listening...")
def add_details(credentials, public_key_client, client):
    # If the action is add_details, store the new credentials
    email, user, pword, service = credentials.split('\n')
    print(f"Received credentials: {email}, {user}, {pword}, {service}")
    # check if there already exists a database for the email, if not then create one. This database is different from the users database
    cred_table.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (email,))
    if cred_table.fetchone() is None:
        cred_table.execute(f'''
            CREATE TABLE {email} (
                user TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                service TEXT NOT NULL
            );
        ''')
        print(f"New table '{email}' created in {cred_db}")
    else:
        print(f"Table '{email}' already exists in {cred_db}")
    # check if the user already exists in the database
    cred_table.execute(f"SELECT user FROM {email} WHERE service = ?", (service,))
    if cred_table.fetchone() is not None:
        # if there already exists details for the service, ask the user if they want to update the details
        print("Details already exist for the service!")
        client.send("2".encode())
        response = client.recv(1024).decode()
        if response == "yes":
            # update the username and the password for the service
            cred_table.execute(f"UPDATE {email} SET user = ?, password = ? WHERE service = ?", (user, pword, service))
            conn.commit()
            print(f"Details updated for email: {email}")
            client.send("1".encode())
            # print whats in the entire credentials database
            cred_table.execute("SELECT * FROM users")
            print(cred_table.fetchall())
        else:
            print("Details not updated!")
            client.send("0".encode())
    else:
        # insert values such that the key is the user and the value is the password and service
        cred_table.execute(f"INSERT INTO {email} VALUES (?, ?, ?)", (user, pword, service))
        conn.commit()
        print(f"New details stored for email: {email}")
        client.send("1".encode())
        # print whats in the entire credentials database
        cred_table.execute("SELECT * FROM users")
        print(cred_table.fetchall())

def get_details(credentials, public_key_client, client):
    email, service = credentials.split('\n')
    print(f"Received credentials: {email}, {service}")
    # check if the user already exists in the database
    cred_table.execute(f"SELECT user, password FROM {email} WHERE service = ?", (service,))
    if cred_table.fetchone() is None:
        # if the service does not exist, send a message to the client
        print("Details do not exist for the service!")
        client.send("0".encode())
    else:
        # if the service exists, send the details to the client
        cred_table.execute(f"SELECT user, password FROM {email} WHERE service = ?", (service,))
        user, pword = cred_table.fetchone()
        print(f"Details for service: {service} are {user}, {pword}")
        # encrypt the details and send them to the client
        details = f"{user}\n{pword}"
        encrypted_details = rsa.encrypt(details.encode(), public_key_client)
        client.send("1".encode())
        client.send(encrypted_details)
        print("Details sent to the client!")
while True:
    client, address = server.accept()
    print(f"Connection established with {address}")
    with open("client_public_key.pem", "rb") as key_file:
        public_key_data = key_file.read()
    # format the key data as a public key
    public_key_client = rsa.PublicKey.load_pkcs1(public_key_data)
    # Receive encrypted credentials from the client
    encrypted_credentials = client.recv(1024)
    print("Received encrypted credentials from the client.")
    action, credentials = encrypted_credentials.split(b'\n', 1)  # split using bytes, not string
    action = action.decode()  # decode action to string
    print(f"Received action: {action}")
    if action == "exit":
        print("Client requested to exit.")
        client.close()
        break
    credentials = rsa.decrypt(credentials, private_key_server).decode()
    # Query the database for the email
    if action == "signup":
        email, password_hash = credentials.split('\n')
        print(f"Received credentials: {email}, {password_hash}")
        # check if email is already in the database
        cred_table.execute("SELECT email FROM users WHERE email = ?", (email,))
        if cred_table.fetchone() is not None:
            print("Signup Failed! Email already exists.")
            client.send("0".encode())
            client.close()
            continue
        # If the action is signup, store the new credentials
        hashed_password = bcrypt.hashpw(password_hash.encode(), bcrypt.gensalt())
        print(f"Hashed password: {hashed_password}")
        cred_table.execute("INSERT INTO users VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        print(f"New credentials stored for email: {email}")
        client.send("1".encode())
        # print whats in the database
        cred_table.execute("SELECT * FROM users")
        print(cred_table.fetchall())

    elif action == "login":
        email, password_hash = credentials.split('\n')
        print(f"Received credentials: {email}, {password_hash}")
        # If the action is login, check the credentials
        cred_table.execute("SELECT password FROM users WHERE email = ?", (email,))
        row = cred_table.fetchone()
        print("row", row)
        if row is not None:
            # If the email is in the database, check if the password is correct
            if bcrypt.checkpw(password_hash.encode(), row[0]):
                print("Login Successful!")
                client.send("1".encode())
                ready_message = client.recv(1024).decode()
                while ready_message == "ready":
                    # get ready to recieve more credentials from the client, essentially starting the loop again
                    encrypted_credentials = client.recv(1024)
                    action, credentials = encrypted_credentials.split(b'\n', 1)
                    action = action.decode()
                    print(f"Received action: {action}")
                    if action == "exit":
                        print("Client requested to exit.")
                        client.close()
                        break
                    credentials = rsa.decrypt(credentials, private_key_server).decode()
                    if action == "adddetails":
                        add_details(credentials, public_key_client, client)
                    elif action == "get_details":
                        get_details(credentials, public_key_client, client)
            else:
                print("Login Failed! Incorrect password.")
                client.send("0".encode())
        else:
            print("Login Failed! Email not found.")
            client.send("0".encode())

server.close()
conn.close()