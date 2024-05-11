import socket
import sqlite3
import rsa
import hashlib
import schnorr
import cert_functions as certificate
from OpenSSL import crypto


DATABASE_NAME = 'password_manager.db'
server_name = "Password_Manager" # CN (Common name)
id_s = "password@manager.com" # id of the server
org_y = "CS362/Spring2024" # organization name(O)

# just in case we need to change these
countryName = "NT" # C
localityName = "Sonipat" # L
stateOrProvinceName = "Haryana" # ST
organizationUnitName = "Ashoka University" # OU

def create_self_cert(auth_key):
    self_cert = certificate.create_certificate(auth_key, auth_key, id_s, server_name, "self_c.crt",
    countryName, localityName, stateOrProvinceName, org_y, organizationUnitName)
    return self_cert

# check if private_key_server file already exists
try:
    with open("dsa_private_key.pem", "rb") as key_file:
        auth_private_key = key_file.read()
except FileNotFoundError:
    auth_key = certificate.create_dsa_key(server_name)
    with open("dsa_private_key.pem", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, auth_key))
    with open("dsa_public_key.pem", "wb") as key_file:
        key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, auth_key))

with open("dsa_private_key.pem", "rb") as key_file:
    auth_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
with open("dsa_public_key.pem", "rb") as key_file:
    auth_public_key = crypto.load_publickey(crypto.FILETYPE_PEM, key_file.read())


# check if self_cert file already exists
try:
    with open("self_cert.pem", "rb") as cert_file:
        self_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
except FileNotFoundError:
    self_cert = create_self_cert(auth_private_key)
    with open("self_cert.pem", "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self_cert))




# Create a new SQLite database or connect to an existing one
conn = sqlite3.connect(DATABASE_NAME)
cur = conn.cursor()
(public_key_server, private_key_server)= rsa.newkeys(512)
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


def create_rsa_cert():
    rsa_key = certificate.create_rsa_key(server_name)
    public_key_server= crypto.dump_publickey(crypto.FILETYPE_PEM, rsa_key)
    private_key_server= crypto.dump_privatekey(crypto.FILETYPE_PEM, rsa_key)
    new_cert = certificate.create_certificate(rsa_key, auth_private_key, id_s, server_name, "cert_S.crt", 
    countryName, localityName, stateOrProvinceName, org_y, organizationUnitName, self_cert)
    return new_cert, public_key_server, private_key_server

def send_cert(dsa_cert, client):
    cert= (crypto.dump_certificate(crypto.FILETYPE_PEM, dsa_cert).decode())
    print(cert)
    client.send(cert.encode())
    print("------CERTIFICATE SENT------")

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
    # check if the hash is equal to the challenge
    if h_prime.decode()==c:
        return True
    else:
        return False

def server_stuff(server_socket):
    # Accept incoming connection and get client socket
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
    data= client_socket.recv(1024).decode()
    print(f"Received data: {data}")
    # split the data into the signature, public key and the message(username)
    message, signatureC, signatureZ = data.split('\n')
    # convert user from binary to string
    message_i = ''.join(chr(int(message[i:i+8], 2)) for i in range(0, len(message), 8))
    # get the public key of the client from the table users_pk
    cur.execute("SELECT p, g, h FROM users_pk WHERE username = ?", (message_i,))
    publicKey = cur.fetchone()
    # convert publicKey into a list
    p, g, h = int(publicKey[0]), int(publicKey[1]), int(publicKey[2])
    verification = schnorr.verify(int(signatureC), int(signatureZ), int(p), int(g), int(h), message)
    if verification == True:
        # send message approved to clienta
        client_socket.send("True".encode())
        return True
    else:
        # send message denied to client
        client_socket.send("False".encode())
        print("DENIED")
        client_socket.close()
        return False

def start_server():
    # create certificates for the server
    dsa_cert, public_key_server, private_key_server= create_rsa_cert()
    #public_key_server.to_cryptography_key().public_bytes(crypto.FILETYPE_PEM, None)
    #private_key_server.to_cryptography_key().private_bytes(crypto.FILETYPE_PEM, None)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 65432))
    server_socket.listen(5)
    print("Server listening on port 65432...")
    client_socket, addr = server_socket.accept()
    print(f"Connection established from {addr}")
    msg= client_socket.recv(1024)
    if msg.decode()=="hello":
        print("Hello received from client")
        # send a message initiating the handshake
        client_socket.send("hello".encode())
        # receive the public key from the client
        verify=schnorr_stuff(client_socket)
        if verify==True:
            server_stuff(server_socket)
        else:
            client_socket.close()
            server_socket.close()
            start_server()
    elif msg.decode()=="register":
        print("Registering new user...")
        client_socket.close()
        server_stuff(server_socket)
        # close the server socket and stop using address
        server_socket.close()
        start_server()
    elif msg.decode()=="verify":
        print("Verification starting...")
        client_socket.send("proceed".encode())
        send_cert(dsa_cert, client_socket)
        response= client_socket.recv(2048).decode()
        client_socket.close()
        server_socket.close()
        if response=="valid":
            print("Verified")
            start_server()
        else:
            print("Not verified")
    else:
        # send message denied to client
        client_socket.send("False".encode())
        client_socket.close()
        server_socket.close()
        start_server()

if __name__ == '__main__':
    start_server()
