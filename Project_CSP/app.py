import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from flask import Flask, render_template, request, redirect, session
from flask import g as dbg
import socket
import rsa
import hashlib
import sqlite3
from Crypto.Util import number
import schnorr
import cert_functions as certificate
from OpenSSL import crypto

DATABASE_NAME= "user_authentication.db" # Database that stores user information to authenticate user
# Connect to the database
conn = sqlite3.connect(DATABASE_NAME)
cur = conn.cursor()

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

# Define the columns for the 'users' table
users_columns = '''
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
'''

# Define the columns for the 'users_pk' table
users_pk_columns = '''
    username TEXT PRIMARY KEY,
    p TEXT NOT NULL,
    g TEXT NOT NULL,
    h TEXT NOT NULL
'''

# Call the function for creating the 'users' table
create_table_if_not_exists(cur, 'users', users_columns)

# Call the function for creating the 'users_pk' table
create_table_if_not_exists(cur, 'users_pk', users_pk_columns)

# Create a database to store the alpha values for each user
create_table_if_not_exists(cur, 'users_alpha', 'username TEXT PRIMARY KEY, alpha TEXT NOT NULL')

app = Flask(__name__)
dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/')
server_address = '127.0.0.1'
port = 65432
server_name = "Client_App" # CN (Common name)
id_s = "client@app.com" # id of the server
org_y = "CS362/Spring2024" # organization name(O)

# just in case we need to change these
countryName = "NT" # C
localityName = "Sonipat" # L
stateOrProvinceName = "Haryana" # ST
organizationUnitName = "Ashoka University" # OU

def create_self_cert(auth_key):
    self_cert = certificate.create_certificate(auth_key, auth_key, id_s, server_name, "client_root.crt",
    countryName, localityName, stateOrProvinceName, org_y, organizationUnitName)
    return self_cert

# check if client_private_key file already exists
try:
    with open("client_private_key.pem", "rb") as key_file:
        client_private_key = key_file.read()
    client_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, client_private_key)
except FileNotFoundError:
    # generate RSA key pair
    client_private_key = certificate.create_dsa_key(server_name)
    with open("client_private_key.pem", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_private_key))
    with open("client_public_key.pem", "wb") as key_file:
        key_file.write(crypto.dump_publickey(crypto.FILETYPE_PEM, client_private_key))

with open("client_private_key.pem", "rb") as key_file:
    auth_private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
with open("client_public_key.pem", "rb") as key_file:
    auth_public_key = crypto.load_publickey(crypto.FILETYPE_PEM, key_file.read())

# check if client_root.cert file already exists
try:
    with open("client_root.pem", "rb") as cert_file:
        client_root_cert = cert_file.read()
    client_root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, client_root_cert)
except FileNotFoundError:
    # create a self-signed certificate for DSA key pair
    client_root_cert = create_self_cert(auth_private_key)
    with open("client_root.pem", "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_root_cert))


print("client_root_cert:",client_root_cert)

def create_rsa_cert(auth_key, issuer_cert):
    rsa_key = certificate.create_rsa_key(server_name)
    public_key_server= crypto.dump_publickey(crypto.FILETYPE_PEM, rsa_key)
    private_key_server= crypto.dump_privatekey(crypto.FILETYPE_PEM, rsa_key)
    new_cert = certificate.create_certificate(rsa_key, auth_key, id_s, server_name, "client_rsa.crt", 
    countryName, localityName, stateOrProvinceName, org_y, organizationUnitName, issuer_cert)
    return new_cert, public_key_server, private_key_server

client_cert, client_pkey, client_skey= create_rsa_cert(auth_private_key, client_root_cert)
client_pkey, client_skey = crypto.load_publickey(crypto.FILETYPE_PEM, client_pkey), crypto.load_privatekey(crypto.FILETYPE_PEM, client_skey)
client_pkey, client_skey = client_pkey.to_cryptography_key(), client_skey.to_cryptography_key()

with open("self_cert.pem", "rb") as cert_file:
    self_cert = cert_file.read()
self_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self_cert)
# print("self_cert:",self_cert)

def verify_server(self_cert):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_address, port))
    # Sending hello to the server.
    client.send("verify".encode())
    print("------ ASKED SERVER FOR VERIFICATION------")
    # Receiving the message from the server.
    pro = client.recv(1024).decode()
    print("------RECEIVED RESPONSE FROM SERVER------")
    if pro == "proceed":
        # Receiving the server's response.
        cert = client.recv(2048).decode()
        print("------RECEIVED CERTIFICATE FROM SERVER------")
        print("cert:",cert)
        # convert the certificate to a certificate object
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        # convert the certificate to a certificate object
        #self_cert = crypto.load_certificate(crypto.FILETYPE_PEM, self_cert)
        p_key_S= certificate.extract_public_key(cert)
        server_pubkey= p_key_S.to_cryptography_key()
        print("Server public key:",server_pubkey)
        # Verify the certificate
        cert_chain = [cert, self_cert]
        result = certificate.CertVerify(cert_chain)
        if result:
            print("Certificate is valid.")
            mes= certificate.rsa_encrypt("valid", server_pubkey)
            client.send(mes)
            m=client.recv(1024).decode()
            if m=="Verify":
                print("------RECEIVED VERIFICATION REQUEST FROM SERVER------")
                certificate.send_cert(client_cert, client)
                print("------SENT CERTIFICATE TO SERVER------")
                ver= client.recv(1024).decode()
                if ver=="True":
                    print("Certificate is valid.")
                    client.close()
                    return server_pubkey
                else:
                    print("Certificate is invalid.")
                    # close the connection
                    client.close()
                    return False
        else:
            print("Certificate is invalid.")
            client.send("close".encode())
            # close the connection
            client.close()
            return False


public_key_server = verify_server(self_cert)
if public_key_server == False:
    print("Server verification failed!")
    exit()

def get_db():
    db = getattr(dbg, '_database', None)
    if db is None:
        db = dbg._database = sqlite3.connect(DATABASE_NAME)
    return db

# Register new user
def register_user(username, password):
    conn = get_db()
    cur = conn.cursor()
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
    conn=get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ? AND password = ?", (username, password))
    if cur.fetchone() is not None:
        print("LOGIN SUCCESSFUL")
        return True
    return False

# Generate some random security key
app.secret_key = 'your_secret_key_here'
(public_key_client, private_key_client) = rsa.newkeys(2048)
with open("client_public_key.pem", "wb") as key_file:
    key_file.write(public_key_client.save_pkcs1())
'''with open("server_public_key.pem", "rb") as key_file:
    public_key_data = key_file.read()
# format the key data as a public key
public_key_server = rsa.PublicKey.load_pkcs1(public_key_data)'''

with open("client_public_key.pem", "wb") as key_file:
    key_file.write(public_key_client.save_pkcs1())


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(dbg, '_database', None)
    if db is not None:
        db.close()

# Home page route
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'existing_user' in request.form:
            return redirect('/login')
        elif 'new_user' in request.form:
            return redirect('/register')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'new_user' in request.form:
            return redirect('/register')
        elif 'existing_user' in request.form:
            conn=get_db()
            cur = conn.cursor()
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_address, port))
            # Existing user login
            username = request.form['username']
            password = request.form['password']
            # Encrypt the information before sending it to the server
            response= login_user(username, password)  
            if response == True:
                ###Schnorr signature stuff here###
                # Send server a hello message, initiating the Schnorr protocol
                client_socket.send("hello".encode())
                r= client_socket.recv(2048).decode()
                if r=="hello":
                    # get the user's pk and alpha from the database
                    cur.execute("SELECT p, g, h FROM users_pk WHERE username = ?", (username,))
                    publicKey = cur.fetchone()
                    # convert publicKey into a list
                    p, g, h = int(publicKey[0]), int(publicKey[1]), int(publicKey[2])
                    cur.execute("SELECT alpha FROM users_alpha WHERE username = ?", (username,))
                    alpha = cur.fetchone()
                    # convert alpha into a string
                    alpha = int(alpha[0]) # Take from a file labelled alpha val from the user system
                    message = ''.join(format(ord(i), '08b') for i in username) # Convert the username to binary
                    signatureC, signatureZ = schnorr.sign(message, alpha, p, g, h)
                    # Send the signature to the server along with the username and the public key
                    client_socket.send(f"{message}\n{signatureC}\n{signatureZ}".encode())
                    resp = client_socket.recv(2048).decode() # This will be the result of the verification
                    if resp == "True":
                        session['username'] = username
                        return redirect('/dashboard')
                    else:
                        return redirect('/login')
            else:
                return redirect('/login')
    return render_template('login.html')

# Registration route

'''
We have to use schnorr here when registering the user
'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = str(request.form['username'])
        password = str(request.form['password'])
        if username and password:
            response= register_user(username, password)
            if response == True:
                publicKey, alpha = schnorr.keygen()
                p, g, h = str(publicKey[1]), str(publicKey[0]), str(publicKey[2])
                conn=get_db()
                cur = conn.cursor()
                cur.execute('INSERT INTO users_pk (username, p, g, h) VALUES (?, ?, ?, ?)', (username, p, g, h))
                conn.commit()
                cur.execute('INSERT INTO users_alpha (username, alpha) VALUES (?, ?)', (username, str(alpha)))
                conn.commit()
                # send p,g,h to the server
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((server_address, port))
                client_socket.send("register".encode())
                client_socket.close()
                action = 'register'
                credentials = f"{action},{username}\n{p}\n{g}\n{h}"
                encrypted_credentials = certificate.rsa_encrypt(credentials, public_key_server)
                client_socket_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket_2.connect((server_address, port))
                client_socket_2.send(encrypted_credentials)
                '''
                This is where we will conduct the schnorr protocol test
                '''
                startState = client_socket_2.recv(2048).decode()
                if startState == "start":
                    y, beta = schnorr.genY(int(p), int(g))
                    client_socket_2.send(str(y).encode())
                    # Recieve the challenge from the server
                    c = int(client_socket_2.recv(2048).decode())
                    z = schnorr.genZ(int(p), beta, c, alpha)
                    # Send z to the server
                    client_socket_2.send(str(z).encode())
                    # Recieve the server's response
                    response = client_socket_2.recv(2048).decode()
                    if response == "verified":
                        client_socket_2.close()
                        session['username'] = username
                        return redirect('/login')
                    else:
                        client_socket_2.close()
                        return redirect('/register')
            else:
                return redirect('/register')
        else:
            # Handle case where username or password is empty
            return redirect('/register')
    return render_template('register.html')

# Dashboard route (protected)
@app.route('/dashboard')
# Check if the user is logged in before accessing the dashboard
# Also create the various buttons and input fields for the dashboard
def dashboard():
    if 'username' in session:
        return dash_app.index()
    else:
        return redirect('/')

# Dash layout
'''
Will have two functions that this page can do:
function 1: retrieve password for a specific site
function 2: add a new site, name and password
'''
dash_app.layout = html.Div(style={'background-color': '#333', 'color': '#fff', 'height': '100vh', 'display': 'flex', 'flex-direction': 'column', 'align-items': 'center', 'justify-content': 'center'}, children=[
    html.H1('Password Manager Dashboard', style={'font-size': '32px', 'font-weight': 'bold', 'color': '#ffa500', 'text-shadow': '2px 2px 4px #000000', 'margin-bottom': '20px'}),
    
    html.Div(style={'display': 'flex', 'justify-content': 'center', 'width': '100%'}, children=[
        # Left half for adding passwords
        html.Div(style={'width': '50%', 'padding': '20px', 'display': 'flex', 'flex-direction': 'column', 'align-items': 'center'}, children=[
            html.H2('Add New Site', style={'font-size': '32px', 'font-weight': 'bold', 'color': '#ffa500', 'text-shadow': '2px 2px 4px #000000', 'margin-bottom': '20px', 'text-align': 'center'}),
            html.Div([
            dcc.Input(id='new-site-name-input', type='text', placeholder='Enter new site name', style={'margin-bottom': '10px'}),
            dcc.Input(id='new-name-input', type='text', placeholder='Enter your name', style={'margin-bottom': '10px'}),
            dcc.Input(id='new-password-input', type='password', placeholder='Enter new password', style={'margin-bottom': '10px'})
            ], style={'display': 'flex', 'flex-direction': 'column', 'align-items': 'center'}),
            html.Button('Add Site', id='add-site-btn', n_clicks=0, style={'display': 'block', 'margin': 'auto', 'margin-top': '10px', 'background-color': '#007bff', 'color': '#fff', 'padding': '10px 20px', 'font-size': '16px', 'border': 'none', 'border-radius': '4px', 'cursor': 'pointer', 'transition': 'background-color 0.3s ease'})
        ]),
        
        # Right half for retrieving passwords
        html.Div(style={'width': '50%', 'padding': '20px'}, children=[
            html.H2('Retrieve Password', style={'font-size': '32px', 'font-weight': 'bold', 'color': '#ffa500', 'text-shadow': '2px 2px 4px #000000', 'margin-bottom': '20px', 'text-align': 'center'}),
            html.Div([
                dcc.Input(id='site-name-input', type='text', placeholder='Enter site name', style={'margin-bottom': '10px'}),
                html.Button('Retrieve Password', id='retrieve-password-btn', n_clicks=0, style={'display': 'block', 'margin': 'auto', 'margin-top': '10px', 'background-color': '#007bff', 'color': '#fff', 'padding': '10px 20px', 'font-size': '16px', 'border': 'none', 'border-radius': '4px', 'cursor': 'pointer', 'transition': 'background-color 0.3s ease'})
            ], style={'display': 'flex', 'flex-direction': 'column', 'align-items': 'center'})
        ])
    ]),
    
    html.Div(style={'text-align': 'center', 'margin-top': '20px'}, children=[
        html.Button('Exit', id='exit-btn', n_clicks=0, style={'background-color': 'lightcoral', 'color': 'black', 'padding': '10px 20px', 'font-size': '16px', 'border': 'none', 'border-radius': '4px', 'cursor': 'pointer', 'transition': 'background-color 0.3s ease'})
    ]),
    
    html.Div(id='password-display'),
    html.Div(id='add-site-output'),
    
    dcc.Location(id='url', refresh=True)
])

@dash_app.callback(
    Output('password-display', 'children'),
    [Input('retrieve-password-btn', 'n_clicks')],
    [State('site-name-input', 'value')]
)
def retrieve_password(n_clicks, site_name):
    if n_clicks is None or n_clicks == 0:
        return None

    if not site_name:
        return html.Div([
            html.P("Please enter a site name.", style={'color': 'red'})
        ])

    if 'username' not in session:
        return html.Div([
            html.P("Please log in to retrieve passwords.", style={'color': 'red'})
        ])

    # Create a new client socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_address, port))

    action = 'retrieve'
    user= str(session['username'])
    credentials = f"{action},{user}\n{site_name}"
    encrypted_credentials = certificate.rsa_encrypt(credentials, public_key_server)
    client_socket.send(encrypted_credentials)
    response = client_socket.recv(2048)
    response = certificate.rsa_decrypt(response, client_skey)
    client_socket.close()  # Close the socket after receiving the response

    if response != "Password not found.":
        return html.Div([
            html.H3(f"Password for {site_name}: {response}", style={'color': 'green'})
        ])
    else:
        return html.Div([
            html.P("Password not found.", style={'color': 'red'})
        ])

@dash_app.callback(
    Output('add-site-output', 'children'),
    [Input('add-site-btn', 'n_clicks')],
    [State('new-site-name-input', 'value'), State('new-password-input', 'value'), State('new-name-input', 'value')]
)
def add_new_site(n_clicks, new_site_name, new_password, new_name):
    if n_clicks is None or n_clicks == 0:
        return None

    if not new_site_name or not new_password or not new_name:
        return html.Div([
            html.P("Please fill in all fields.", style={'color': 'red'})
        ], style={'text-align': 'center'})

    if 'username' not in session:
        return html.Div([
            html.P("Please log in to add new sites.", style={'color': 'red'})
        ], style={'text-align': 'center'})

    # Create a new client socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_address, port))

    action = 'add'
    user= str(session['username'])
    credentials = f"{action},{user}\n{new_site_name}\n{new_password}\n{new_name}"
    encrypted_credentials = certificate.rsa_encrypt(credentials, public_key_server)
    client_socket.send(encrypted_credentials)
    response = client_socket.recv(2048).decode()
    client_socket.close()  # Close the socket after receiving the response

    if response == "1":
        return html.Div([
            html.H3(f"New site '{new_site_name}' added successfully!", style={'color': 'green'})
        ], style={'text-align': 'center'})
    elif response == "2":
        return html.Div([
            html.P("Site already exists. Please try again.", style={'color': 'red'})
        ], style={'text-align': 'center'})
    else:
        return html.Div([
            html.P("Failed to add new site. Please try again.", style={'color': 'red'})
        ], style={'text-align': 'center'})


@dash_app.callback(
    Output('url', 'pathname'),
    [Input('exit-btn', 'n_clicks')]
)
def exit_dashboard(n_clicks):
    if n_clicks > 0:
        return '/'

if __name__ == '__main__':
    app.run(debug=False)
