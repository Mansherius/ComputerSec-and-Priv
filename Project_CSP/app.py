# app.py
from flask import Flask, render_template, request, redirect, session
import dash
from dash import html
from dash import dcc
import socket

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/')

server_address = '127.0.0.1'
port = 65432

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_address, port))

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        client.send(f"{username}\n{password}".encode())
        response = client.recv(1024).decode()
        if response == "1":
            session['username'] = username
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid login credentials')
    return render_template('login.html')

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
    html.H1('Password Manager Dashboard'),
    html.Div(id='dashboard-content'),
    dcc.Input(id='site-name-input', type='text', placeholder='Enter site name'),
    html.Button('Retrieve Password', id='retrieve-password-btn', n_clicks=0),
    html.Div(id='password-display')
])

@dash_app.callback(
    dash.dependencies.Output('password-display', 'children'),
    [dash.dependencies.Input('retrieve-password-btn', 'n_clicks')],
    [dash.dependencies.State('site-name-input', 'value')]
)
def retrieve_password(n_clicks, site_name):
    if n_clicks > 0:
        if 'username' in session:
            client.send(f"retrieve,{session['username']},{site_name}".encode())
            response = client.recv(1024).decode()
            if response != "Password not found.":
                return html.Div([
                    html.H3(f"Password for {site_name}: {response}")
                ])
            else:
                return html.Div([
                    html.P("Password not found.")
                ])
        else:
            return html.Div([
                html.P("Please log in to retrieve passwords.")
            ])
    return None

if __name__ == '__main__':
    app.run(debug=True)
