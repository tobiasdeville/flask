from flask import Flask, render_template_string, request, session, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, current_user
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SECURITY_PASSWORD_SALT'] = os.urandom(16).hex()
app.config['WTF_CSRF_ENABLED'] = True

# Security headers
Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://openfpcdn.io'],
})

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
seasurf = SeaSurf(app)

# Define models FIRST
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    device_fingerprint = db.Column(db.String(255), nullable=True)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

# NOW set up Flask-Security-Too
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

with app.app_context():
    db.create_all()

# Templates
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Login</title>
  <script src="https://openfpcdn.io/fingerprintjs/v4"></script>
  <script>
    async function setFingerprint() {
      const fp = await FingerprintJS.load();
      const result = await fp.get();
      document.getElementById('fingerprint').value = result.visitorId;
    }
    window.onload = setFingerprint;
  </script>
</head>
<body>
  <h2>Login</h2>
  <form method="POST" action="{{ url_for('login') }}">
    <input type="email" name="email" placeholder="Email" required /><br>
    <input type="password" name="password" placeholder="Password" required /><br>
    <input type="hidden" name="fingerprint" id="fingerprint" />
    {{ csrf_token() }}
    <button type="submit">Login</button>
  </form>
  {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
  <h2>Welcome, {{ email }}!</h2>
  <p>Your device fingerprint: {{ fingerprint }}</p>
  <a href="{{ url_for('security.logout') }}">Logout</a>
</body>
</html>
"""

@app.route('/login', methods=['GET', 'POST'])
def login():
    from flask_security.utils import verify_and_update_password, login_user
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        fingerprint = request.form['fingerprint']
        user = User.query.filter_by(email=email).first()
        if user and verify_and_update_password(password, user):
            # Store fingerprint for anomaly detection
            user.device_fingerprint = fingerprint
            db.session.commit()
            login_user(user)
            session['device_fingerprint'] = fingerprint
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    # Anomaly detection: compare stored and current fingerprint
    stored_fp = current_user.device_fingerprint
    current_fp = session.get('device_fingerprint')
    if stored_fp and current_fp and stored_fp != current_fp:
        from flask_security.utils import logout_user
        logout_user()
        abort(403, 'Device anomaly detected: fingerprint mismatch')
    return render_template_string(DASHBOARD_HTML, email=current_user.email, fingerprint=stored_fp)

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)
