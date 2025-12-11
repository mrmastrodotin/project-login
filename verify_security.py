import requests
from app import app, db, User

BASE_URL = "http://127.0.0.1:5000"

def test_password_hashing():
    print("\n[1] TEST: Password Hashing")
    with app.app_context():
        users = User.query.all()
        if not users:
            print("   INFO: No users found. Creating a test user...")
            # Create a user to test processing
            from flask_bcrypt import Bcrypt
            bcrypt = Bcrypt(app)
            hashed = bcrypt.generate_password_hash("password123").decode('utf-8')
            user = User(username="security_test", email="test@secure.com", password=hashed)
            db.session.add(user)
            db.session.commit()
            users = [user]

        for user in users:
            print(f"   User: {user.username}")
            print(f"   Stored Password: {user.password}")
            if len(user.password) == 60 and user.password.startswith("$2b$"):
                print("   PASS: Password appears to be a valid Bcrypt hash.")
            else:
                print("   FAIL: Password does not look like a Bcrypt hash!")

def test_rate_limiting():
    print("\n[2] TEST: Rate Limiting (5 attempts/min)")
    # We need to maintain a session or IP. Requests does this by default.
    url = f"{BASE_URL}/login"
    
    print("   Sending 7 login requests...")
    for i in range(1, 8):
        response = requests.post(url, data={'email': 'fake@email.com', 'password': 'wrong'}, allow_redirects=False)
        status = response.status_code
        if status == 429:
            print(f"   Request {i}: Status {status} (Too Many Requests) -> BLOCKED AS EXPECTED")
            return
        elif status == 200:
             # Flask-Limiter usually returns 429. If it renders the template (200), it might not have blocked yet.
             print(f"   Request {i}: Status {status} (Allowed)")
        else:
             print(f"   Request {i}: Status {status}")
    
    print("   WARNING: Rate limit was not triggered in 7 attempts.")

def test_honeypot():
    print("\n[3] TEST: Bot Protection (Honeypot)")
    url = f"{BASE_URL}/register"
    # 'bot_catcher' is the hidden field. A bot would fill it.
    data = {
        'username': 'bot_user',
        'email': 'bot@spam.com',
        'password': 'password',
        'confirm_password': 'password',
        'bot_catcher': 'I am a bot' 
    }
    
    # We need to bypass CSRF for this script or use a valid token. 
    # Since CSRF is enabled, a raw post without token will fail CSRF check first (400 Bad Request).
    # We should fetch the form first to get CSRF token if we wanted a perfect test, 
    # but the honeypot logic runs AFTER form validation (or inside it).
    # However, if we don't send CSRF token, it fails BEFORE checking honeypot.
    
    # Let's use app context to check the logic directly if possible, or use a session to get csrf.
    client = requests.Session()
    # Get register page to get CSRF token
    r = client.get(url)
    if r.status_code == 200:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(r.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})
        if csrf_token:
            data['csrf_token'] = csrf_token['value']
    
    # Post with filled honeypot
    response = client.post(url, data=data, allow_redirects=True) 
    
    # The code says if bot_catcher: flash('Account created!') and redirect to login.
    # But it DOES NOT create the user.
    
    with app.app_context():
        user = User.query.filter_by(username='bot_user').first()
        if user:
            print("   FAIL: Bot user was created in the database!")
        else:
            # Check if we were redirected to login (indicating the 'fake success' path)
            if "/login" in response.url:
                 print("   PASS: Bot was redirected to login (Fake Success).")
                 print("   PASS: Bot user was NOT created in database.")
            else:
                 print(f"   INFO: Response URL: {response.url}")

if __name__ == "__main__":
    try:
        test_password_hashing()
        test_rate_limiting()
        test_honeypot()
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Make sure the server is running on port 5000!")
