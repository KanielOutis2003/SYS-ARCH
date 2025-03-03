from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import logging
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

# Initialize Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = 'your_very_secure_secret_key_here'
app.permanent_session_lifetime = timedelta(minutes=30)  # Session expires after 30 minutes

# Configure logging
logging.basicConfig(
    filename='error.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Define the upload folder and allowed file extensions
UPLOAD_FOLDER = 'static/uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to get a database connection
def get_db():
    try:
        db = sqlite3.connect('students.db')
        db.row_factory = sqlite3.Row
        return db
    except Exception as e:
        logging.error(f"Database connection error: {str(e)}")
        raise

# Function to initialize the database
def init_db():
    with app.app_context():
        db = get_db()
        # Drop existing tables
        db.execute('DROP TABLE IF EXISTS sessions')
        db.execute('DROP TABLE IF EXISTS students')
        
        # Create tables from schema
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        
        # Add admin user if it doesn't exist
        try:
            admin_exists = db.execute('SELECT id FROM students WHERE username = ?', ('admin',)).fetchone()
            if not admin_exists:
                hashed_password = generate_password_hash('admin')
                db.execute(''' 
                    INSERT INTO students (
                        idno, lastname, firstname, middlename, 
                        course, year_level, email, username, password, user_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    'ADMIN001',  # idno
                    'Admin',     # lastname
                    'System',    # firstname
                    '',         # middlename
                    'ADMIN',     # course
                    0,           # year_level
                    'admin@example.com',  # email
                    'admin',     # username
                    hashed_password,  # password
                    'admin'      # user_type
                ))
                db.commit()
                print("Admin user created successfully")
        except Exception as e:
            print(f"Error creating admin user: {str(e)}")
            logging.error(f"Error creating admin user: {str(e)}")

# Login required decorator with error handling
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'user_id' not in session:
                flash('Please login first.', 'error')
                return redirect(url_for('index'))
            # Check if session is expired
            if 'last_activity' in session:
                last_activity = datetime.fromtimestamp(session['last_activity'])
                if (datetime.now() - last_activity).total_seconds() > 1800:  # 30 minutes
                    session.clear()
                    flash('Session expired. Please login again.', 'warning')
                    return redirect(url_for('index'))
            session['last_activity'] = datetime.now().timestamp()
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in login_required decorator: {str(e)}")
            flash('An unexpected error occurred.', 'error')
            return redirect(url_for('index'))
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

# Route for handling login
@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM students WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']  # Store the internal database ID in the session
            session['user_type'] = user['user_type']
            session['student_name'] = f"{user['firstname']} {user['lastname']}"
            session['student_id'] = user['idno']  # Store the student ID number (idno) in the session
            session['last_activity'] = datetime.now().timestamp()
            flash('Successfully logged in!', 'success')
            
            if user['user_type'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['user_type'] == 'staff':
                return redirect(url_for('staff_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        flash('An error occurred during login.', 'error')
        return redirect(url_for('index'))

# Route for handling lab rules
@app.route('/lab-rules')
def lab_rules():
    return render_template('lab_rules.html')

# Route for editing student record
@app.route('/edit-record')
@login_required
def edit_record():
    student_id = session.get('student_id')
    if not student_id:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    db = get_db()
    student = db.execute('SELECT * FROM students WHERE idno = ?', (student_id,)).fetchone()
    if not student:
        return "Student not found", 404

    return render_template('edit_record.html', student=student)

# Route for updating student record
@app.route('/update-record', methods=['POST'])
def update_record():
    student_id = session.get('student_id')
    if not student_id:
        return redirect(url_for('login'))

    db = get_db()
    student = db.execute('SELECT * FROM students WHERE idno = ?', (student_id,)).fetchone()
    if not student:
        return "Student not found", 404

    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form










@app.route('/dashboard')
@login_required
def dashboard():
    try:
        return render_template('student_dashboard.html', 
                             student_name=session.get('student_name', 'Student'))
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/view-sessions')
@login_required
def view_sessions():
    # TODO: Implement view sessions functionality
    flash('View sessions feature coming soon!')
    return redirect(url_for('dashboard'))


# Route for the make-reservation page
@app.route('/make-reservation')
def make_reservation():
    return render_template('make_reservation.html')

# Route for handling form submission
@app.route('/submit-reservation', methods=['POST'])
def submit_reservation():
    # Fetch the logged-in student's ID and name from the session
    student_id = session.get('student_id')
    student_name = session.get('student_name')
    if not student_id or not student_name:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Retrieve form data
    date = request.form.get('date')
    time = request.form.get('time')
    lab = request.form.get('lab')
    purpose = request.form.get('purpose')

    # Create a new reservation record
    new_reservation = Reservation(
        student_id=student_id,
        student_name=student_name,
        date=date,
        time=time,
        lab=lab,
        purpose=purpose
    )

    # Save the reservation to the database
    db.session.add(new_reservation)
    db.session.commit()

    # Redirect back to the student dashboard
    return redirect(url_for('student_dashboard'))

# Route to view all reservations
@app.route('/view-reservations')
def view_reservations():
    # Fetch all reservations from the database
    reservations = Reservation.query.all()
    return render_template('view_reservations.html', reservations=reservations)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
def register():
    try:
        user_type = request.form['user_type']
        hashed_password = generate_password_hash(request.form['password'])
        db = get_db()

        if user_type == 'staff':
            # Staff registration
            db.execute('''
                INSERT INTO students (
                    idno, lastname, firstname, middlename, 
                    course, year_level, email, username, password, user_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                request.form['idno'],
                request.form['lastname'],
                request.form['firstname'],
                request.form['middlename'],
                request.form['department'],  # department goes into course field
                0,                          # default year_level for staff
                request.form['email'],
                request.form['username'],
                hashed_password,
                'staff'                     # user_type for staff
            ))
        else:
            # Student registration
            db.execute('''
                INSERT INTO students (
                    idno, lastname, firstname, middlename, 
                    course, year_level, email, username, password, user_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                request.form['idno'],
                request.form['lastname'],
                request.form['firstname'],
                request.form['middlename'],
                request.form['course'],
                request.form['year_level'],
                request.form['email'],
                request.form['username'],
                hashed_password,
                'student'                   # user_type for student
            ))
        
        db.commit()
        print(f"Registration successful for {user_type}")
        flash(f'Registration successful! Please login.', 'success')
    except sqlite3.IntegrityError as e:
        print(f"Registration IntegrityError: {str(e)}")
        flash('Error: ID Number, Email, or Username already exists.', 'error')
    except Exception as e:
        print(f"Registration error: {str(e)}")
        flash('An error occurred during registration.', 'error')
    
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    flash('Page not found.', 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Internal server error: {str(e)}")
    flash('An internal server error occurred.', 'error')
    return redirect(url_for('dashboard'))

@app.before_request
def before_request():
    # Clear session if user closed browser
    if 'user_id' in session and 'last_activity' not in session:
        session.clear()
        flash('Session expired. Please login again.', 'warning')
        return redirect(url_for('index'))

# Add after the get_db() function
def is_admin(user_id):
    try:
        db = get_db()
        user = db.execute('SELECT user_type FROM students WHERE id = ?', (user_id,)).fetchone()
        return user and user['user_type'] == 'admin'
    except Exception as e:
        logging.error(f"Error checking admin status: {str(e)}")
        return False

# Add admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin(session.get('user_id')):
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Add these new routes before the errorhandler routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    try:
        return render_template('admin/dashboard.html')
    except Exception as e:
        logging.error(f"Admin dashboard error: {str(e)}")
        flash('Error loading admin dashboard.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/students')
@login_required
@admin_required
def admin_students():
    try:
        db = get_db()
        students = db.execute('''
            SELECT id, idno, lastname, firstname, middlename, 
                   course, year_level, email, username 
            FROM students WHERE user_type = 'student'
        ''').fetchall()
        return render_template('admin/students.html', students=students)
    except Exception as e:
        logging.error(f"Admin students view error: {str(e)}")
        flash('Error loading students list.', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/active-sessions')
@login_required
@admin_required
def admin_active_sessions():
    try:
        db = get_db()
        active_sessions = db.execute('''
            SELECT s.*, 
                   st.firstname, st.lastname, st.idno,
                   st.course, st.year_level
            FROM sessions s
            JOIN students st ON s.student_id = st.id
            WHERE s.end_time > datetime('now')
            ORDER BY s.start_time DESC
        ''').fetchall()
        return render_template('admin/active_sessions.html', sessions=active_sessions)
    except Exception as e:
        logging.error(f"Admin active sessions view error: {str(e)}")
        flash('Error loading active sessions.', 'error')
        return redirect(url_for('admin_dashboard'))

# Add staff required decorator
def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_type') != 'staff':
            flash('Staff access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/staff/dashboard')
@login_required
@staff_required
def staff_dashboard():
    try:
        return render_template('staff/dashboard.html')
    except Exception as e:
        logging.error(f"Staff dashboard error: {str(e)}")
        flash('Error loading staff dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/staff/view-sessions')
@login_required
@staff_required
def staff_view_sessions():
    try:
        db = get_db()
        active_sessions = db.execute('''
            SELECT s.*, st.firstname, st.lastname, st.idno,
                   st.course, st.year_level, s.purpose
            FROM sessions s
            JOIN students st ON s.student_id = st.id
            WHERE s.end_time > datetime('now')
            ORDER BY s.start_time DESC
        ''').fetchall()
        return render_template('staff/view_sessions.html', sessions=active_sessions)
    except Exception as e:
        logging.error(f"Staff view sessions error: {str(e)}")
        flash('Error loading sessions.', 'error')
        return redirect(url_for('staff_dashboard'))

@app.route('/staff/session-records')
@login_required
@staff_required
def staff_session_records():
    try:
        db = get_db()
        records = db.execute('''
            SELECT s.*, st.firstname, st.lastname, st.idno,
                   st.course, st.year_level, s.purpose
            FROM sessions s
            JOIN students st ON s.student_id = st.id
            ORDER BY s.created_at DESC
        ''').fetchall()
        return render_template('staff/session_records.html', records=records)
    except Exception as e:
        logging.error(f"Staff session records error: {str(e)}")
        flash('Error loading session records.', 'error')
        return redirect(url_for('staff_dashboard'))

@app.route('/staff/generate-report')
@login_required
@staff_required
def staff_generate_report():
    try:
        year = request.args.get('year', datetime.now().year)
        db = get_db()
        report_data = db.execute('''
            SELECT s.purpose, COUNT(*) as count,
                   strftime('%m', s.reservation_date) as month
            FROM sessions s
            WHERE strftime('%Y', s.reservation_date) = ?
            GROUP BY s.purpose, month
            ORDER BY month, s.purpose
        ''', (str(year),)).fetchall()
        return render_template('staff/generate_report.html', report_data=report_data, year=year)
    except Exception as e:
        logging.error(f"Staff report generation error: {str(e)}")
        flash('Error generating report.', 'error')
        return redirect(url_for('staff_dashboard'))

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)
