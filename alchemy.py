
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, login_user, LoginManager, logout_user, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
import os
import json
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import defaultload
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from flask_mail import Mail,Message
from werkzeug.utils import secure_filename
import datetime as dt


app = Flask(__name__)

with open('config.json') as c:
    params = json.load(c)["params"]

#main config
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious'
app.config['UPLOAD_FOLDER'] = params['upload_location']

#mail settings
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

#gmail authentication
app.config['MAIL_USERNAME'] = 'trackandtriggercsf213@gmail.com'
app.config['MAIL_PASSWORD'] = 'SubVrajArjav'
app.config['MAIL_DEFAULT_SENDER'] = 'trackandtriggercsf213@gmail.com'

mail = Mail(app)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return Users.query.get(int(id))

class Users(db.Model, UserMixin):
    
    __tablename__ = "User_Data"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    role = db.Column(db.String(50), default="User")
    phno = db.Column(db.String(10),default="None")
    addr = db.Column(db.String(250),default="None")
    profile_image = db.Column(db.String(255), default="default.png")
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    gender = db.Column(db.String(10),default="None")
    dob = db.Column(db.String(10),default="None")
    
    
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id
    


@app.route('/', methods=['POST', 'GET'])
def login():
    #checking if API receives a post request(user entering data)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        #retrieving user data from database
        user = Users.query.filter_by(email=email).first()
        #checking if user exists
        if user is None:
            #displaying error message if user not present in database
            flash('User does not exist.', category='error')
            
        else:
            #checking if password matches after decoding it
            checker = check_password_hash(user.password,password)
            if checker:
                flash(f'Logged in successfully!', category='success')               
                login_user(user)
                return redirect(url_for('dash_board'))
            
            else:
                flash('Incorrect password! Try again', category='error')
    return render_template('login.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    
    #checking if the API receives a post request
    if request.method == 'POST':
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = Users.query.filter_by(email=email).first()
        print(password1)
        print(password2)
        #checking if a user of the entered email already exists
        if user:
            flash("An account with this email already exists!", category='error')
        
        #checking if both password fields match
        elif password1 != password2:
            flash('Passwords don\'t match', category='error')
        
        else:
            
            new_user = Users(first_name=" ", last_name=" ", email=email,
                             password=generate_password_hash(password1, method='sha256'), profile_image="default")
            db.session.add(new_user)
            db.session.commit()
            
            token = generate_confirmation_token(new_user.email)
            flash('Account created successfully!', category='success')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('activate.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(new_user.email, subject, html)
            
            login_user(new_user, remember=True)
            return redirect(url_for('dash_board'))
    return render_template('register.html', user = current_user)

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', category='error')
    user = Users.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', category='success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('dash_board'))

@app.route('/set_image', methods=['POST', 'GET'])
@login_required
def set_image():
    if request.method=="POST":
        pic = request.files['pic']
        if not pic:
            flash('No pic uploaded', category='error')
        else:
            filename = secure_filename(pic.filename)
            pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user = Users.query.get_or_404(current_user.id)
            user.profile_image = filename
            db.session.commit()
            return redirect(url_for('profile'))
        
        
        
    return render_template('select_photo.html')

@app.route('/dashboard')
@login_required
def dash_board():
    user = Users.query.get_or_404(current_user.id)
    return render_template('dashboard.html', user=user)

@app.route('/super_user', methods=['POST', 'GET'])
@login_required
def super_user():
    
    all_super_users = Users.query.order_by(Users.id)
    name_list = []
    for u in all_super_users:
        if u.id is not current_user.id:
            name_list.append(u.id)
    
    role_list = ["Super User", "Admin", "User"]
    
    if request.method == "POST":
        role = request.form['role_dropdown']
        id = request.form['name_dropdown']
        ids = request.form.getlist('myCheckBox')
        print(ids)
        user = Users.query.get_or_404(id)
        user.role = role
        db.session.commit()
        flash(f'Assigned {role} role to {user.first_name}', category='success')
        return redirect(url_for('super_user'))
        
    
    return render_template('super_user.html', users = all_super_users, user=current_user, names = name_list, roles = role_list)

@app.route('/get_checkbox', methods=['POST','GET'])
@login_required
def get_checkbox():
    ids = request.form.getlist('myCheckBox')
    role = request.form['role_dropdown']
    if len(ids) == 0:
        flash(f'Select a user', category='error')
    else:
        for id in ids:
            user = Users.query.get_or_404(id)
            user.role = role
            db.session.commit()
            flash(f'Assigned {role} role to {user.first_name}', category='success')
    return redirect(url_for('super_user'))

@app.route('/delete_user/<int:user_id>', methods=['POST','GET'])
@login_required
def delete_users(user_id):
    user_to_delete = Users.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash("User has been deleted.", category='success')
            
    return redirect(url_for('super_user'))
    
@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():

    
    if(current_user.dob is not None):
        age = get_age(current_user.dob)
    else:
        age=""
    return render_template('new_profile.html', user = current_user,age=age)

@app.route('/edit-profile', methods=['POST','GET'])
@login_required
def edit_profile():
    if request.method == "POST":
        first_name = request.form.get('first_name')
        current_user.first_name = first_name
        last_name = request.form.get('last_name')
        current_user.last_name = last_name
        phno = request.form.get('phno')
        current_user.phno = phno
        addr = request.form.get('addr')
        current_user.addr = addr
        gender = request.form.get("inlineRadioOptions")
        current_user.gender = gender
        dob = request.form.get("dob")
        current_user.dob = dob
        db.session.commit()
        age = get_age(current_user.dob)
        return render_template('new_profile.html', user = current_user, age=age)
    return render_template('edit-profile.html',user = current_user)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])



def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    email = False
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

@app.route('/display_image')
def display_image():
    return redirect(url_for('static',filename = 'Profile_Pictures/'+current_user.profile_image))

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

def get_age(str):
    today = dt.date.today()
    #str = input("Give your date of birth in yyyy-mm-dd: ")
    year = int(str[0:4])
    month = int(str[5:7])
    d = int(str[8:])
    b_date = dt.date(year,month,d)
    t_difference = today - b_date
    age = t_difference.days
    return (int(age/365))

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)