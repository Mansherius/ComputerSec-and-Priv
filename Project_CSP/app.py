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

app = Flask(__name__)
# Generate some random security key
app.secret_key = 'your_secret_key_here'

dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/')
server_address = '127.0.0.1'
port = 65432

(public_key_client, private_key_client) = rsa.newkeys(2048)

with open("client_public_key.pem", "wb") as key_file:
    key_file.write(public_key_client.save_pkcs1())
with open("server_public_key.pem", "rb") as key_file:
    public_key_data = key_file.read()
# format the key data as a public key
public_key_server = rsa.PublicKey.load_pkcs1(public_key_data)


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
                r= client_socket.recv(1024).decode()
                if r=="hello":
                    # get the user's pk and alpha from the database
                    cur.execute("SELECT p, g, h FROM users_pk WHERE username = ?", (username,))
                    p,g,h1= cur.fetchone()
                    cur.execute("SELECT alpha FROM users_alpha WHERE username = ?", (username,))
                    alpha= cur.fetchone()
                    # convert alpha into a string
                    alpha = alpha[0] # Take from a file labelled alpha val from the user system
                    signature = schnorr.sign(username, publicKey, alpha)
                    # resp = client_socket.recv(1024).decode() # This will be the result of the verification
                    if resp == True:
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

                conn=get_db()
                cur = conn.cursor()
                cur.execute('INSERT INTO users_pk (username, p, g, h) VALUES (?, ?, ?, ?)', (username, publicKey[1], publicKey[0], publicKey[2]))
                conn.commit()
                cur.execute('INSERT INTO users_alpha (username, alpha) VALUES (?, ?)', (username, alpha))
                conn.commit()
                session['username'] = username
                return redirect('/login')
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
dash_app.layout = html.Div([
    html.H1('Password Manager Dashboard', style={'text-align': 'center'}),
    html.Div(id='dashboard-content'),
    html.Hr(),
    # Retrieve Password Section
    html.Div([
        dcc.Input(id='site-name-input', type='text', placeholder='Enter site name', style={'margin-right': '10px'}),
        html.Button('Retrieve Password', id='retrieve-password-btn', n_clicks=0, style={'background-color': 'lightgrey'})
    ], style={'text-align': 'center'}),
    html.Div(id='password-display'),
    html.Hr(),
    # Add New Site Section
    html.Div([
        dcc.Input(id='new-site-name-input', type='text', placeholder='Enter new site name', style={'margin-right': '10px'}),
        dcc.Input(id='new-name-input', type='text', placeholder='Enter your name', style={'margin-right': '10px'}),
        dcc.Input(id='new-password-input', type='password', placeholder='Enter new password', style={'margin-right': '10px'}),
        html.Button('Add Site', id='add-site-btn', n_clicks=0, style={'background-color': 'lightblue'})
    ], style={'text-align': 'center'}),
    html.Div(id='add-site-output'),
    html.Hr(),
    # Exit Button
    html.Div([
        html.Button('Exit', id='exit-btn', n_clicks=0, style={'background-color': 'lightcoral', 'color': 'black'})
    ], style={'text-align': 'center'}),
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
    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key_server)
    client_socket.send(encrypted_credentials)
    response = client_socket.recv(1024)
    response = rsa.decrypt(response, private_key_client).decode()
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
    encrypted_credentials = rsa.encrypt(credentials.encode(), public_key_server)
    client_socket.send(encrypted_credentials)
    response = client_socket.recv(1024).decode()
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
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=False)
