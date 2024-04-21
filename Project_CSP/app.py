import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
from flask import Flask, render_template, request, redirect, session
import socket

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/')

server_address = '127.0.0.1'
port = 65432

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_address, port))

# Home page route
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'existing_user' in request.form:
            return redirect('/login')
        elif 'new_user' in request.form:
            return redirect('/register')
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'existing_user' in request.form:
            # Existing user login
            username = request.form['username']
            password = request.form['password']
            credentials = f"{username}\n{password}"
            # Send the credentials along with the action to the server
            action = 'login'
            client_socket.send(f"{action},{credentials}".encode())

            response = client_socket.recv(1024).decode()
            if response == "1":
                session['username'] = username
                return redirect('/dashboard')
            else:
                return render_template('login.html', error='Invalid login credentials')
    return render_template('login.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username and password:
            credentials = f"{username}\n{password}"
            # Send the credentials along with the action to the server
            action = 'register'
            client_socket.send(f"{action},{credentials}".encode())
            
            response = client_socket.recv(1024).decode()
            if response == "1":
                session['username'] = username
                return redirect('/dashboard')
            else:
                return render_template('register.html', error='Registration failed. Please try again.')
        else:
            # Handle case where username or password is empty
            return render_template('register.html', error='Username and password are required.')

    return render_template('register.html')

# Dashboard route (protected)
@app.route('/dashboard')
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
dash_app.layout = html.Div([
    html.H1('Password Manager Dashboard', style={'text-align': 'center'}),
    html.Div(id='dashboard-content'),
    html.Hr(),
    html.Div([
        dcc.Input(id='site-name-input', type='text', placeholder='Enter site name'),
        html.Button('Retrieve Password', id='retrieve-password-btn', n_clicks=0)
    ], style={'text-align': 'center'}),
    html.Div(id='password-display')
])

@dash_app.callback(
    Output('password-display', 'children'),
    [Input('retrieve-password-btn', 'n_clicks')],
    [State('site-name-input', 'value')]
)
def retrieve_password(n_clicks, site_name):
    if n_clicks > 0:
        if 'username' in session:
            client_socket.send(f"retrieve,{session['username']},{site_name}".encode())
            response = client_socket.recv(1024).decode()
            if response != "Password not found.":
                return html.Div([
                    html.H3(f"Password for {site_name}: {response}", style={'color': 'green'})
                ])
            else:
                return html.Div([
                    html.P("Password not found.", style={'color': 'red'})
                ])
        else:
            return html.Div([
                html.P("Please log in to retrieve passwords.", style={'color': 'red'})
            ])
    return None

if __name__ == '__main__':
    app.run(debug=True)
