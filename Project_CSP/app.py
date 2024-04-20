from flask import Flask, render_template, request, redirect, session
import dash
from dash import html
from dash import dcc

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set a secret key for session management
dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/')

# Simulated user database (replace with actual database integration)
users = {'user1': 'password1', 'user2': 'password2'}

# We will be using an SQLite3 database that will be in another file and will query it from here

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect('/dashboard')
        else:
            return 'Invalid username or password. Please try again.'

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
    html.Div(id='dashboard-content')
])

if __name__ == '__main__':
    app.run(debug=True)
