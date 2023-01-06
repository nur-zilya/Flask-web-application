import os
from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

app = Flask(__name__)
# Old SQLite
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
# New SQL MySQL
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:1234@localhost/our_users'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234@localhost/our_users'
# Secret Key!
app.config['SECRET_KEY'] = "123456"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    surname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return  check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name

class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    surname = StringField("Surname", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match! ')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField("Submit")

class NamerForm(FlaskForm):
    name = StringField("What's Your Name", validators=[DataRequired()])
    submit = SubmitField("Submit")

# quiz_host = os.environ.get('FLASK_HOST')
# quiz_port = os.environ.get('FLASK_PORT')

questions = [
    {
        "id": "1",
        "question": "What is the Capital of Syria?",
        "answers": ["a) Beirut", "b) Damascus", "c) Baghdad"],
        "correct": "b) Damascus"
    },
    {
        "id": "2",
        "question": "What is the square root of Pi?",
        "answers": ["a) 1.7724", "b) 1.6487", "c) 1.7872"],
        "correct": "a) 1.7724"
    },
    {
        "id": "3",
        "question": "How many counties are there in England?",
        "answers": ["a) 52", "b) 48", "c) 45"],
        "correct": "b) 48"
    }
]
@app.route("/", methods=['POST', 'GET'])
def index():
    return render_template("index.html", data=questions)

@app.route('/user/<name>')
def user(name):
	return render_template("user.html", user_name=name)

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(name=form.name.data, surname=form.surname.data,username=form.username.data, email=form.email.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.surname.data = ''
        form.password_hash.data = ''

        flash("User Added Successfully!")
    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html",
        form=form,
        name=name,
        our_users=our_users)


# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500

@app.route("/quiz", methods=['POST', 'GET'])
def quiz():
    result = 0
    total = 0
    s=''
    for question in questions:
        s=s+str(request.form.getlist(question['id']))+'<br>'
    return(str(s))

@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    form = NamerForm()

    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("Form Submitted Successfully!")

    return render_template("name.html",
                           name = name,
                           form = form)

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Succesful!")
                return redirect(url_for('test'))
            else:
                flash("Wrong password - Try Again!")
        else:
            flash("That user doesn't exist!")
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	flash("You Have Been Logged Out!  Thanks For Stopping By...")
	return redirect(url_for('login'))

@app.route('/test', methods=['GET', 'POST'])
@login_required
def test():
    return render_template('test.html')


if __name__ == "__main__":
    # app.run(host=quiz_host, port=quiz_port)
    app.run(debug=True)
