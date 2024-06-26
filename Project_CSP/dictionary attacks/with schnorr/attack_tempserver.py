import socket
import sqlite3
import rsa
import hashlib
import schnorr_2 as schnorr
import threading


DATABASE_NAME = 'password_manager.db'

# Create a new SQLite database or connect to an existing one
conn = sqlite3.connect(DATABASE_NAME)
cur = conn.cursor()

# Check if the table 'users' already exists in the database
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
if cur.fetchone() is None:
    # Create a new table for storing username and password
    cur.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
    ''')
    print(f"New table 'users' created in {DATABASE_NAME}")
else:
    print(f"Table 'users' exists in {DATABASE_NAME}")

(public_key_server, private_key_server) = rsa.newkeys(2048)


# Save the public key to a file
with open("server_public_key.pem", "wb") as key_file:
    key_file.write(public_key_server.save_pkcs1())

def create_table_if_not_exists(cur, table_name, columns):
    cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}';")
    if cur.fetchone() is None:
        # Create a new table
        cur.execute(f'''
            CREATE TABLE {table_name} (
                {columns}
            );
        ''')
        print(f"New table '{table_name}' created")
    else:
        print(f"Table '{table_name}' exists")

# Create a table to store the public keys of the users
# Define the columns for the 'users_pk' table
users_pk_columns = '''
    username TEXT PRIMARY KEY,
    p TEXT NOT NULL,
    g TEXT NOT NULL,
    h TEXT NOT NULL
'''
create_table_if_not_exists(cur, 'users_pk', users_pk_columns)

# Register new user
def register_user(username, password):
    # check if the username starts with a number, if yes then return false
    username= str(username) 
    if username[0].isdigit():
        print("Username cannot start with a number!")
        return False
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
        print("LOGIN SUCCESSFUL")
        return True
    return False

# Function to add a new site with password
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
        print(f"New table {username} created in {DATABASE_NAME}")
    else:
        print(f"Table '{username}' already exists in {DATABASE_NAME}")
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
    # print whats in the entire credentials database
    cur.execute("SELECT * FROM users")
    print(cur.fetchall())
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

def challenge(pk,m,sigma):
    p,g,h= pk
    c,z = sigma
    j= ((g.mod_pow(z, p))*(h.mod_pow(c, p))).mod_inverse(p)
    # concatenate the message and the challenge
    m_prime= str(j)+m
    # hash the concatenated message
    h_prime= hashlib.sha256(m_prime.encode()).hexdigest()
    print(f"Hash of the concatenated message: {h_prime}")
    # check if the hash is equal to the challenge
    if h_prime.decode()==c:
        return True
    else:
        return False

def server_stuff(server_socket):
    # Accept incoming connection and get client socket
    conn = sqlite3.connect(DATABASE_NAME)
    cur = conn.cursor()
    client_socket, addr = server_socket.accept()
    print(f"Connection established from {addr}")
    with open("client_public_key.pem", "rb") as key_file:
        public_key_data = key_file.read()
    # format the key data as a public key
    public_key_client = rsa.PublicKey.load_pkcs1(public_key_data)
    # Receive data from the client
    data = client_socket.recv(2048)
    print(f"Received encrypted data: {data}")
    data= rsa.decrypt(data, private_key_server)
    data= data.decode()
    print(f"Received data: {data}")
    action, args = data.split(',', 1)  # Split into action and arguments

    if action == 'register':
        username, p,g,h= args.split('\n')
        print("REGISTERING NEW USER...")
        print(f"Username: {username}")
        print(f"P: {p}")
        print(f"G: {g}")
        print(f"H: {h}")
        # insert the p,g,h into a table users_pk
        cur.execute('INSERT INTO users_pk (username, p, g, h) VALUES (?, ?, ?, ?)', (username, p, g, h))
        conn.commit()
        print("New user registered")
        client_socket.close()
        return None
    elif action == 'login':
        username, password = args.split('\n')
        print("LOGGING IN USER...")
        print(f"Username: {username}")
        print(f"Password: {password}")

        # Login the user and send response to client
        if login_user(username, password):
            client_socket.send("1".encode())
            client_socket.close()
            server_stuff(server_socket)
        else:
            client_socket.send("0".encode())
            client_socket.close()
            server_stuff(server_socket)

    elif action == 'retrieve':
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
            server_stuff(server_socket)
        else:
            client_socket.send("Password not found.".encode())
            client_socket.close()
            server_stuff(server_socket)

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
            server_stuff(server_socket)
        elif add_new_site(username, new_name, new_site_name, new_password, client_socket)==2:
            client_socket.send("2".encode())
            client_socket.close()
            server_stuff(server_socket)

        else:
            client_socket.send("0".encode())  # Failed to add new site
            client_socket.close()
            server_stuff(server_socket)
def schnorr_stuff(client_socket):
    conn = sqlite3.connect(DATABASE_NAME)
    cur = conn.cursor()
    data= client_socket.recv(1024).decode()
    # split the data into the signature, public key and the message(username)
    message, signatureC, signatureZ = data.split('\n')
    # convert user from binary to string
    message_i = ''.join(chr(int(message[i:i+8], 2)) for i in range(0, len(message), 8))
    print("C is", signatureC)
    print("Z is", signatureZ)
    # get the public key of the client from the table users_pk
    cur.execute("SELECT p, g, h FROM users_pk WHERE username = ?", (message_i,))
    publicKey = cur.fetchone()
    # convert publicKey into a list
    p, g, h = int(publicKey[0]), int(publicKey[1]), int(publicKey[2])
    print("P is", p)
    print("G is", g)
    print("H is", h)
    verification = schnorr.verify(int(signatureC), int(signatureZ), int(p), int(g), int(h), message)
    if verification == True:
        # send message approved to clienta
        client_socket.send("True".encode())
        print("ACCESS GRANTED")
        return True
    else:
        # send message denied to client
        client_socket.send("False".encode())
        print("ACCESS DENIED")
        client_socket.close()
        return False

def handle_client(client_socket):
    msg = client_socket.recv(1024)
    if msg.decode() == "hello":
        print("Hello received from client")
        # send a message initiating the handshake
        client_socket.send("hello".encode())
        # receive the public key from the client
        verify = schnorr_stuff(client_socket)
        if verify == True:
            server_stuff(client_socket)
        else:
            client_socket.close()
    elif msg.decode() == "register":
        print("Registering new user...")
        server_stuff(client_socket)
    else:
        # send message denied to client
        client_socket.send("False".encode())
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(10)
    print("Server listening on port 65432...")
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection established from {addr}")
        # Create a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()
        # set timeout
        client_socket.settimeout(180)
if __name__ == '__main__':
    start_server()
