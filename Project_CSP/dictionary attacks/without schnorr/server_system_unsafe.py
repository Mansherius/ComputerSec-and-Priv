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
cur = conn.cursor()

# Check if the table 'user_service' already exists in the database
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_service';")
if cur.fetchone() is None:
    # Create a new table for storing email and password
    cur.execute('''
        CREATE TABLE user_service (
            service PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    print(f"New table 'user_service' created in {db_file}")
else:
    print(f"Table 'user_service' already exists in {db_file}")

(public_key_server, private_key_server) = rsa.newkeys(2048)


# Save the public key to a file
with open("server_public_key.pem", "wb") as key_file:
    key_file.write(public_key_server.save_pkcs1())

def add_new_site(username, name, site_name, password,client_socket):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (username,))
    if cur.fetchone() is None:
        cur.execute(f'''
            CREATE TABLE "{username}" (
                service TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                user TEXT NOT NULL
            );
        ''')
        print(f"New table {username} created in {db_file}")
    else:
        print(f"Table '{username}' already exists in {db_file}")
    # check if the service already exists in the user's table
    cur.execute(f'''SELECT service FROM "{username}" WHERE service = "{site_name}"''')
    if cur.fetchone() is not None:
        print("Service already exists!")
        return 2
    # insert values such that the key is the user and the value is the password, name and service
    cur.execute(f'''INSERT INTO "{username}" VALUES (?, ?, ?)''', (site_name, password, name))
    conn.commit()
    print(f"New details stored for username: {username}")
    client_socket.send("1".encode())
    return True

# Function to retrieve password for a specific site
def retrieve_password(username, site_name):
    cur.execute(f'''SELECT user, password FROM "{username}" WHERE service = "{site_name}"''')
    data= cur.fetchone()
    print(data)
    if data is not None:
        # if the service exists, send the details to the client
        cur.execute(f'''SELECT user, password FROM "{username}" WHERE service = "{site_name}"''')
        user, pword = cur.fetchone()
        print(f"Details for service: {site_name} are {user}, {pword}")
        return pword
    else:
        print("Details do not exist for the service!")
        return None
def server_stuff(client_socket):
    with open("client_public_key.pem", "rb") as key_file:
        public_key_data = key_file.read()
    # format the key data as a public key
    public_key_client = rsa.PublicKey.load_pkcs1(public_key_data)
    # Receive data from the client
    data = client_socket.recv(1024)
    print(f"Received encrypted data: {data}")
    data= rsa.decrypt(data, private_key_server)
    data= data.decode()
    print(f"Received data: {data}")
    action, args = data.split(',', 1)  # Split into action and arguments

    if action == 'retrieve':
        username, site_name = args.split('\n')
        print("RETRIEVING PASSWORD...")
        print(f"Username: {username}")
        print(f"Site Name: {site_name}")

        # Implement logic to retrieve password for the given site
        password = retrieve_password(username, site_name)
        if password:
            encrypted_password = rsa.encrypt(password.encode(), public_key_client)
            client_socket.send(encrypted_password)
            client_socket.close()
            return 
        else:
            client_socket.send("Password not found.".encode())
            client_socket.close()
            return

    elif action == 'add':
        username, new_site_name, new_password, new_name = args.split('\n')
        print("ADDING NEW SITE...")
        print(f"Username: {username}")
        print(f"New Site Name: {new_site_name}")
        print(f"New Password: {new_password}")
        print(f"New Name: {new_name}")

        # Implement logic to add a new site with the provided password
        if add_new_site(username, new_name, new_site_name, new_password, client_socket)==True:
            client_socket.send("1".encode())  # New site added successfully
            client_socket.close()
            return
        elif add_new_site(username, new_name, new_site_name, new_password, client_socket)==2:
            client_socket.send("2".encode())
            client_socket.close()
            return

        else:
            client_socket.send("0".encode())  # Failed to add new site
            client_socket.close()
            return

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_address, port))
server_socket.listen(1)
print("Server is listening...")
server, address = server_socket.accept()
print(f"Connection established with {address}")
data = server.recv(1024).decode()
print(f"Received hello: {data}")
if data== "hello":
    server.send("hello".encode())
    server_stuff(server)
    server_socket.close()
else:
    server.close()
    server_socket.close()
    print("Invalid data received!")
