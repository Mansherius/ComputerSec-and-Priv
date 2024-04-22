import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from flask import Flask, render_template, request, redirect, session
import socket
import rsa
import hashlib


app = Flask(__name__)
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
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_address, port))
            # Existing user login
            username = request.form['username']
            password = request.form['password']
            # Encrypt the information before sending it to the server
            auth = password.encode()
            action = 'login'
            auth_hash = hashlib.md5(auth).hexdigest() 
            credentials = f"{action},{username}\n{auth_hash}"
            encrypted_credentials = rsa.encrypt(credentials.encode(), public_key_server)
            # Send the credentials along with the action to the server
            client_socket.send(encrypted_credentials)
            response = client_socket.recv(1024).decode()
            if response == "1":
                session['username'] = username
                return redirect('/dashboard')
            else:
                return redirect('/login')
    return render_template('login.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_address, port))
        username = str(request.form['username'])
        password = str(request.form['password'])

        if username and password:
            # Encrypt the information before sending it to the server
            enc = password.encode()
            hash1 = hashlib.md5(enc).hexdigest()
            action = 'register'
            credentials = f"{action},{username}\n{hash1}"
            encrypted_credentials = rsa.encrypt(credentials.encode(), public_key_server)
            # Send the credentials along with the action to the server
            client_socket.send(encrypted_credentials)
            response = client_socket.recv(1024).decode()
            if response == "1":
                session['username'] = username
                return redirect('/dashboard')
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

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
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
        return '/'

if __name__ == '__main__':
    app.run(debug=False)
