from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# Function to create the database and the users table
def create_db():
    conn = sqlite3.connect('users.db')  # Connect to the database (creates the file if it doesn't exist)
    cursor = conn.cursor()

    # Create the 'users' table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Insert some sample users (only if the table is empty)
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:  # If no users exist
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'user'))
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('jecu', 'gwapo'))

    conn.commit()  # Commit changes
    conn.close()   # Close the connection

# Call create_db to set up the database when the app starts
create_db()

# Route to serve the login page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle form submission
@app.route('/submit', methods=['POST'])
def submit():
    username = request.form['username']
    password = request.form['password']
    
    # Validate the user credentials
    if validate_user(username, password):
        return redirect(url_for('welcome'))
    else:
        return "Invalid credentials, please try again."

# Function to validate the user credentials
def validate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()  # If user exists and the password matches, user will not be None
    conn.close()
    return user is not None

# Route to serve a welcome page upon successful login
@app.route('/welcome')
def welcome():
    return "Welcome to the dashboard!"

if __name__ == '__main__':
    app.run(debug=True)
