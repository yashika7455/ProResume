from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, url_for, session, render_template, request, jsonify
from dotenv import load_dotenv
from pymongo import MongoClient, errors
import os
import secrets

# Load environment variables
load_dotenv()

# Create a Flask application
app = Flask(__name__)
# MongoDB setup
try:
    mongo_uri = os.getenv('MONGODB_URL')
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    db = client.get_default_database()  # Use the default database from the URI
    # Try to query the server to verify the connection
    client.server_info()
    print("Connected to MongoDB successfully.")
except errors.ServerSelectionTimeoutError as err:
    print("Failed to connect to MongoDB:", err)
    db = None

app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-default-secret-key')
app.config['SESSION_COOKIE_NAME'] = 'oauth-login-session'

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

linkedin = oauth.register(
    name='linkedin',
    client_id=os.getenv('LINKEDIN_CLIENT_ID'),
    client_secret=os.getenv('LINKEDIN_CLIENT_SECRET'),
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    authorize_params=None,
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    access_token_params=None,
    client_kwargs={'scope': 'r_liteprofile r_emailaddress'},
    userinfo_endpoint='https://api.linkedin.com/v2/me'
)

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    client_kwargs={'scope': 'user:email'},
    userinfo_endpoint='https://api.github.com/user'
)


@app.route('/home')
def home():
    return render_template('index.html')


@app.route('/submit_resume', methods=['POST'])
def submit_resume():
    # Get personal details
    personal_details = {
        "name": request.form.get('name'),
        "email": request.form.get('email'),
        "phone": request.form.get('phone'),
        "address": request.form.get('address'),
        "state": request.form.get('state'),
        "country": request.form.get('country')
    }

    # Get education details
    education_details = {
        "higher_qualification": request.form.get('higher_qualification'),
        "higher_university": request.form.get('higher_university'),
        "higher_stream": request.form.get('higher_stream'),
        "higher_percentage": request.form.get('higher_percentage'),
        "higher_year": request.form.get('higher_year'),
        "higher_state": request.form.get('higher_state')
    }

    # Get skills
    skills = request.form.getlist('skills[]')

    # Combine all data into a single document
    resume_data = {
        "personal_details": personal_details,
        "education_details": education_details,
        "skills": skills
    }

    try:
        # Print resume_data to debug
        print(resume_data)

        # Insert the document into MongoDB
        db.resumes.insert_one(resume_data)
    except Exception as e:
        print(f"Error inserting data: {e}")
        return "An error occurred", 500
    return redirect(url_for('dashboard'))


@app.route('/logingoogle')
def logingoogle():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    redirect_uri = url_for('authorize_google', _external=True)
    print(f"Generated redirect URI for Google: {redirect_uri}")  # Debugging
    return google.authorize_redirect(redirect_uri, state=state)


@app.route('/loginlinkedin')
def loginlinkedin():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    redirect_uri = url_for('authorize_linkedin', _external=True)
    print(f"Generated redirect URI for LinkedIn: {redirect_uri}")  # Debugging
    return linkedin.authorize_redirect(redirect_uri, state=state)


@app.route('/logingithub')
def logingithub():
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    redirect_uri = url_for('authorize_github', _external=True)
    print(f"Generated redirect URI for GitHub: {redirect_uri}")  # Debugging
    return github.authorize_redirect(redirect_uri, state=state)


@app.route('/authorize/google')
def authorize_google():
    request_state = request.args.get('state')
    session_state = session.pop('oauth_state', None)
    if not request_state or session_state != request_state:
        return 'State mismatch. Possible CSRF attack.', 400

    token = google.authorize_access_token()
    id_token = token.get('id_token')
    nonce = session.pop('nonce', None)
    claims = google.parse_id_token(token, nonce=nonce)
    print(claims)
    if claims.get('iss') != 'https://accounts.google.com':
        return 'Invalid issuer', 400

    user_info = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()
    email = user_info['email']
    name = user_info['name']
    picture = user_info['picture']

    session['email'] = user_info['email']
    session['name'] = user_info['name']
    session['picture'] = user_info['picture']

    # Check if the email already exists in MongoDB
    existing_user = db.resumes.find_one({"personal_details.email": email})

    if existing_user:
        # Email exists, redirect to dashboard
        return redirect(url_for('dashboard'))
    return redirect('/form')


@app.route('/authorize/linkedin')
def authorize_linkedin():
    request_state = request.args.get('state')
    session_state = session.pop('oauth_state', None)
    print(f"Request state: {request_state}, Session state: {session_state}")  # Debugging
    if not request_state or session_state != request_state:
        print("State mismatch or possible CSRF attack.")  # Debugging
        return 'State mismatch. Possible CSRF attack.', 400

    token = linkedin.authorize_access_token()
    user_info_email = linkedin.get(
        'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))').json()
    user_info_profile = linkedin.get(
        'https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))').json()

    email = user_info_email['email']
    name = user_info_profile['name']
    picture = user_info_profile['picture']

    session['email'] = user_info_email['elements'][0]['handle~']['emailAddress']
    session[
        'name'] = f"{user_info_profile['firstName']['localized']['en_US']} {user_info_profile['lastName']['localized']['en_US']}"
    session['picture'] = user_info_profile['profilePicture']['displayImage~']['elements'][0]['identifiers'][0][
        'identifier']

    # Check if the email already exists in MongoDB
    existing_user = db.resumes.find_one({"personal_details.email": email})

    if existing_user:
        # Email exists, redirect to dashboard
        return redirect(url_for('dashboard'))

    return redirect(url_for('form'))


@app.route('/authorize/github')
def authorize_github():
    request_state = request.args.get('state')
    session_state = session.pop('oauth_state', None)
    print(f"Request state: {request_state}, Session state: {session_state}")  # Debugging
    if not request_state or session_state != request_state:
        print("State mismatch or possible CSRF attack.")  # Debugging
        return 'State mismatch. Possible CSRF attack.', 400

    token = github.authorize_access_token()
    user_info = github.get('https://api.github.com/user').json()
    emails_info = github.get('https://api.github.com/user/emails').json()

    primary_email = next((email['email'] for email in emails_info if email['primary']), None)

    session['email'] = primary_email
    session['name'] = user_info.get('name', user_info.get('login'))  # Use login as fallback
    session['picture'] = user_info.get('avatar_url')

    # Check if the email already exists in MongoDB
    existing_user = db.resumes.find_one({"personal_details.email": primary_email})

    if existing_user:
        # Email exists, redirect to dashboard
        return redirect(url_for('dashboard'))

    return redirect(url_for('form'))


@app.route('/authorize_login', methods=['POST'])
def authorize_login():
    email = request.form.get('email')
    mpass = request.form.get('password')
    existing_user = db.resumes.find_one({"personal_details.email": email})
    # print(existing_user)
    if existing_user:
        user_pass = existing_user.get('personal_details', {}).get('password')
        if user_pass and user_pass == mpass:
            session['email'] = email
            session['name'] = existing_user.get('personal_details', {}).get('name')
            user_pic = existing_user.get('personal_details', {}).get('pic')
            if user_pic:
                session['picture'] = user_pic
            else:
                session['picture'] = "onlinepic"
            return redirect(url_for('dashboard'))
    return redirect(url_for('form'))


@app.route('/authorize_signup', methods=['POST'])
def authorize_signup():
    name = request.form.get('name')
    email = request.form.get('email')
    mpass = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    existing_user = db.resumes.find_one({"personal_details.email": email})
    print(email)
    if not existing_user:
        if mpass == confirm_password:
            session['email'] = email
            session['name'] = name
            session["picture"] = "online pic"
            return redirect(url_for('form'))
    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('email', None)
    session.clear()
    return redirect('/')


# Define routes to serve the HTML files
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/resume')
def resume():
    return render_template('resume.html')


@app.route('/blog')
def blog():
    return render_template('blog.html')


@app.route('/contact')
def contact():
    return render_template('contactus.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/form')
def form():
    print(
        f"Form session data: email={session.get('email')}, name={session.get('name')}, picture={session.get('picture')}")  # Debugging
    return render_template('form.html', email=session.get('email'), name=session.get('name'),
                           picture=session.get('picture'))


@app.route('/getTemplateList')
def get_template_list():

    skip = int(request.args.get('skip', 0))
    print(skip)
    # Query the database, sort by "uniqueid", and limit to 10 items
    templates = db.template.find({}, {'_id': 0, 'template': 1}).sort('uniqueid', 1).skip(skip).limit(9)

    # Extract the "template" keys
    template_list = [template['template'] for template in templates]

    # Return the list as a JSON response
    return jsonify(template_list)


@app.route('/dashboard')
def dashboard():
    print(
        f"Dashboard session data: email={session.get('email')}, name={session.get('name')}, picture={session.get('picture')}")  # Debugging
    if 'email' in session and 'name' in session and 'picture' in session:
        try:
            # Query to find the first 10 templates sorted by unique_id
            templates = db.template.find().sort('unique_id', 1).limit(10)
            # Convert the query result to a list and return as JSON
            result = list(templates)
            tmplist = []
            for template in result:
                if 'template' in template:
                    print(template['template'])
        except Exception as e:
            return str(e), 500

        return render_template('dashboard.html', email=session['email'], name=session['name'],
                               picture=session['picture'])
    else:
        return redirect(url_for('form'))


if __name__ == '__main__':
    # Run the Flask application
    app.run(debug=True, port=5002)
