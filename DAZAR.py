from flask import Flask, render_template, request, jsonify, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import time
import json

app = Flask(__name__)

API_KEY = '768ef179c15c9d463b7d194f0556d164c1fb2cb9097b884e14657f726123afe7'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# طرق التطبيق
@app.route('/')
def home2():
    return render_template('home2.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['psw']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return 'هذا البريد الإلكتروني مستخدم بالفعل!'

        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('home2'))

    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['psw']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return 'فشل تسجيل الدخول. يرجى التحقق من بيانات الدخول.'

    return render_template('signin.html')

@app.route('/signout')
@login_required
def signout():
    logout_user()  # تسجيل الخروج باستخدام Flask-Login
    return redirect(url_for('home2'))

@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/home2')
def home():
    return render_template('home2.html')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/result')
def result():
    ip_results = request.args.get('ip_results')
    url_results = request.args.get('url_results')
    file_results = request.args.get('file_results')
    return render_template('result.html',
                           ip_results=json.loads(ip_results) if ip_results else [],
                           url_results=json.loads(url_results) if url_results else [],
                           file_results=json.loads(file_results) if file_results else [])

@app.route('/scan_ip', methods=['POST'])
def scan_ip():
    ip_addresses = request.form.get('ip', '').split(',')
    ip_results = []
    for ip in ip_addresses:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip.strip()}',
            headers={'x-apikey': API_KEY}
        )
        if response.status_code == 200:
            ip_results.append(response.json())
        else:
            ip_results.append({'error': f'Failed to scan IP: {ip}'})
    return redirect(url_for('result', ip_results=json.dumps(ip_results)))

@app.route('/scan', methods=['POST'])
def scan():
    links = request.form.get('link', '').split(',')
    url_results = []
    for link in links:
        response = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers={'x-apikey': API_KEY},
            data={'url': link.strip()}
        )
        if response.status_code == 200:
            url_id = response.json().get('data', {}).get('id')
            if url_id:
                time.sleep(30)
                report = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{url_id}',
                    headers={'x-apikey': API_KEY}
                )
                if report.status_code == 200:
                    report_json = report.json()
                    report_json['url'] = link.strip()
                    url_results.append(report_json)
        else:
            url_results.append({'error': f'Failed to scan link: {link}'})
    return redirect(url_for('result', url_results=json.dumps(url_results)))
@app.route('/upload', methods=['POST'])
def upload():
    uploaded_files = request.files.getlist('file')
    file_results = []
    for file in uploaded_files:
        files = {'file': (file.filename, file.stream, file.content_type)}
        response = requests.post(
            'https://www.virustotal.com/api/v3/files',
            headers={'x-apikey': API_KEY},
            files=files
        )
        if response.status_code == 200:
            file_id = response.json().get('data', {}).get('id')
            if file_id:
                time.sleep(30)
                report = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{file_id}',
                    headers={'x-apikey': API_KEY}
                )
                if report.status_code == 200:
                    report_json = report.json()
                    report_json['type'] = 'file'
                    report_json['filename'] = file.filename
                    file_results.append(report_json)
        else:
            file_results.append({'error': 'Failed to upload file'})
    return redirect(url_for('result', file_results=json.dumps(file_results)))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)