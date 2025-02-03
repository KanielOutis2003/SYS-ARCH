import sqlite3

def get_user_by_username(username):
    """Retrieve user from the database by username."""
    conn = sqlite3.connect('users.db')  # Connect to the database
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()  # Fetch the first matching record
    conn.close()  # Close the connection
    return user

def validate_user(username, password):
    """Check if the provided username and password are correct."""
    user = get_user_by_username(username)
    if user and user[2] == password:  # user[2] is the password column
        return True
    return False
