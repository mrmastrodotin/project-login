from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, ValidationError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

app = Flask(__name__)

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

# CONFIGURATION
app.config['SECRET_KEY'] = 'dev-secret-key-change-this-in-prod' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# INITIALIZING SECURITY TOOLS
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# DATABASE MODEL
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False) # Stores the HASH

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# FORMS
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    bot_catcher = StringField('Middle Name') # HONEYPOT

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# ROUTES
@app.route("/")
def home():
    return render_template('home.html')

@app.route("/presentation")
def presentation():
    return render_template('presentation.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # BOT DEFENSE
        if form.bot_catcher.data:
            flash('Account created!', 'success')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

@app.route("/live-demo")
def live_demo():
    return render_template('live_demo.html', title='Security Console')

@app.route("/api/get-hash")
def get_hash():
    # Helper for the 'Vault' demo to show a real hash
    user = User.query.first()
    if user:
        return {'username': user.username, 'hash': user.password}
    else:
        return {'username': 'No User', 'hash': 'No users found in DB'}

@app.route("/api/search")
def search_user():
    query = request.args.get('query')
    # SECURE: SQLAlchemy uses parameterized queries
    user = User.query.filter_by(username=query).first()
    if user:
        return {'found': True, 'username': user.username, 'email': user.email}
    else:
        return {'found': False}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
