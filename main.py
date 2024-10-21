from flask import Flask, render_template, request, redirect, make_response, url_for
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib

app = Flask(__name__)

# Initialize Firebase Admin SDK
cred = credentials.Certificate('key.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

# Helper to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Helper to check if user is logged in
def get_logged_in_user():
    cookie = request.cookies.get('Logged')
    if cookie:
        username, _ = cookie.split('.')
        return username
    return None

# Helper to get client IP address
def get_client_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

# Route: Home
@app.route('/', methods=['GET', 'POST'])
def home():
    username = get_logged_in_user()
    pastes = []

    if request.method == 'POST':
        search_query = request.form['search_query']
        # Search pastes by name or content
        pastes_ref = db.collection('pastes').where('name', '>=', search_query).where('name', '<=', search_query + '\uf8ff').get()
        pastes = [paste.to_dict() for paste in pastes_ref]
    else:
        # Get all pastes for display on the home page
        pastes_ref = db.collection('pastes').get()
        pastes = [paste.to_dict() for paste in pastes_ref]

    return render_template('home.html', username=username, title='Home', pastes=pastes)

# Route: Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_repeat = request.form['password_repeat']

        if password != password_repeat:
            return 'Passwords do not match.'

        # Check if user exists
        users_ref = db.collection('users').where('username', '==', username).get()
        if users_ref:
            return 'Username already exists.'

        # Create new user
        db.collection('users').add({
            'username': username,
            'password': hash_password(password)
        })

        return redirect(url_for('login'))

    return render_template('register.html', title='Register')

# Route: Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists
        users_ref = db.collection('users').where('username', '==', username).get()
        if not users_ref:
            return 'Invalid username or password.'

        # Verify password
        user_data = users_ref[0].to_dict()
        if user_data['password'] != hash_password(password):
            return 'Invalid username or password.'

        # Set cookie
        resp = make_response(redirect(url_for('home')))
        resp.set_cookie('Logged', f'{username}.{hash_password(password)}')

        return resp

    return render_template('login.html', title='Login')

# Route: Profile (Change username)
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    username = get_logged_in_user()
    if not username:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form['new_username']

        # Prevent duplicate usernames
        users_ref = db.collection('users').where('username', '==', new_username).get()
        if users_ref:
            return 'Username already exists.'

        # Update username in the database
        users_ref = db.collection('users').where('username', '==', username).get()
        doc_id = users_ref[0].id
        db.collection('users').document(doc_id).update({'username': new_username})

        # Update cookie
        resp = make_response(redirect(url_for('profile')))
        resp.set_cookie('Logged', f'{new_username}.{hash_password(password)}')

        return resp

    return render_template('profile.html', username=username, title='Profile')

# Route: Logout
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('home')))
    resp.delete_cookie('Logged')
    return resp

# Route: Create Paste
@app.route('/create', methods=['GET', 'POST'])
def create_paste():
    username = get_logged_in_user()

    if request.method == 'POST':
        paste_name = request.form['paste_name']
        paste_content = request.form['paste_content']
        author = username if username else 'Anonymous'

        # Check if paste with the same name exists
        pastes_ref = db.collection('pastes').where('name', '==', paste_name).get()
        if pastes_ref:
            return 'A paste with this name already exists.'

        # Save the paste
        db.collection('pastes').add({
            'name': paste_name,
            'content': paste_content,
            'author': author,
            'views': 0  # Initialize the view count to 0
        })

        return redirect(url_for('view_paste', pastename=paste_name))

    return render_template('create_paste.html', username=username, title='Create Paste')

# Route: View Paste (with view count)
@app.route('/paste/<pastename>')
def view_paste(pastename):
    username = get_logged_in_user()
    client_ip = get_client_ip()

    # Retrieve the paste by name
    pastes_ref = db.collection('pastes').where('name', '==', pastename).get()
    if not pastes_ref:
        return 'Paste not found.'

    paste_data = pastes_ref[0].to_dict()
    doc_id = pastes_ref[0].id

    # Check if the paste has been viewed by this IP or user
    viewed_cookie = request.cookies.get(f'viewed_{pastename}')

    if not viewed_cookie:
        # Increment the view count in the database
        new_view_count = paste_data.get('views', 0) + 1
        db.collection('pastes').document(doc_id).update({'views': new_view_count})

        # Set a cookie to track that this user/IP has viewed the paste
        resp = make_response(render_template('view_paste.html', paste=paste_data))
        resp.set_cookie(f'viewed_{pastename}', f'{client_ip or username}:{pastename}')
        return resp

    return render_template('view_paste.html', paste=paste_data)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=1000, debug=True)
