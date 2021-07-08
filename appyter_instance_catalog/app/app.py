import os
import flask
import flask_whooshalchemy as wa
import email_validator
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user, UserMixin, LoginManager, login_user, logout_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_security import Security, SQLAlchemyUserDatastore
from flask_navigation import Navigation
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from dotenv import load_dotenv
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash

from flask_wtf import FlaskForm
from wtforms import SubmitField, SelectField, RadioField, HiddenField, StringField, IntegerField, FloatField, DateField
from wtforms.validators import InputRequired, Length, Regexp, NumberRange, DataRequired, URL
from flask_wtf import Form
from flask_wtf.file import FileField, FileAllowed, FileRequired
from datetime import datetime, date
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

#UNTESTED????
engine = create_engine(
    "sqlite://", 
    connect_args={"check_same_thread": False}, 
    poolclass=StaticPool
)
load_dotenv(verbose=True)

ROOT_PATH = os.environ.get('ROOT_PATH', '/appyter_instance_catalog/')
# Load any additional configuration parameters via
#  environment variables--`../.env` can be used
#  for sensitive information!

app = flask.Flask(__name__,
  static_url_path=ROOT_PATH + 'static',
)

app.config['SECRET_KEY'] ='RCTeD3ObFv5jWZuyx440tu3CZNQz'

Bootstrap(app)
nav = Navigation(app)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///databases/instance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_BINDS'] = {'users':'sqlite:///databases/users.db', 'approved':'sqlite:///databases/approved.db', 'role':'sqlite:///databases/role.db', 'user_roles':'sqlite:///databases/user_roles.db'}
app.config['DEBUG'] = True
#app.config['WHOOSH_BASE'] = 'whoosh'
db = SQLAlchemy(app)


###ADMIN###

class MyModelView(ModelView):
  def is_accessible(self):
    return current_user.is_authenticated
  
  def inaccessible_callback(self, name, **kwargs):
    return redirect(url_for('login'))

class MyAdminIndexView(AdminIndexView):
  def is_accessible(self):
    return current_user.is_authenticated
  def inaccessible_callback(self, name, **kwargs):
    return redirect(url_for('login'))





###DATABASES###
class UserRoles(db.Model):
  __bind_key__ = "user_roles"
  __tablename__ = "user_roles"
  id = db.Column(db.Integer(), primary_key=True)
  user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
  role_id = db.Column(db.Integer(), db.ForeignKey('role.id', ondelete='CASCADE'))

  def __init__(self, user_id, role_id):
    self.user_id = user_id
    self.role_id = role_id

class AppyterInstances(db.Model):
  __tablename__ = "instances"
  id = db.Column(db.Integer, primary_key = True)
  title = db.Column(db.String(100), unique=True, nullable = False)
  dateSub = db.Column(db.Date, unique = False, nullable = False)
  authorSub = db.Column(db.String(50), unique = False, nullable = False) #at some point, one-to-many relationship must be established
  authors = db.Column(db.String(200), unique = False, nullable = False)
  affiliations = db.Column(db.String(150), unique = False, nullable = False)
  appyterInstance = db.Column(db.VARCHAR(1700), unique = True, nullable = False) #URL
  originalAppyter = db.Column(db.VARCHAR(1700), unique = True, nullable = False) #URL
  dateCreated = db.Column(db.Date, unique = False, nullable = False)
  references = db.Column(db.String(200), unique = False, nullable = False)
  keywords = db.Column(db.String(200), unique = False, nullable = False)
  #figure out image & abstract later

  def __init__(self, title, dateSub, authorSub, authors, affiliations, appyterInstance, originalAppyter, dateCreated, references, keywords):
    self.title = title
    self.dateSub = dateSub
    self.authorSub = authorSub
    self.authors = authors
    self.affiliations = affiliations 
    self.appyterInstance = appyterInstance
    self.originalAppyter = originalAppyter
    self.dateCreated = dateCreated
    self.references = references
    self.keywords = keywords

  def __repr__(self):
        return '<AppyterInstance %r>' % self.title

class User(db.Model, UserMixin):
  __tablename__ = "users"
  __bind_key__ = 'users'
  id = db.Column(db.Integer, primary_key = True)
  email = db.Column(db.String(120), unique = True)
  password = db.Column(db.String(100))
  name = db.Column(db.String(1000))
  roles = db.relationship('Role', secondary= 'user_roles', backref=db.backref('users', lazy='dynamic'))

  def __init__(self, email, password, name):
    self.email = email
    self.password = password
    self.name = name
   
  def __repr__(self):
        return '<User %r>' % self.name

class ApprovedInstances(db.Model):
  __tablename__ = "approved"
  __bind_key__ = 'approved'
  id = db.Column(db.Integer, primary_key = True)
  title = db.Column(db.String(100), unique=True, nullable = False)
  dateSub = db.Column(db.Date, unique = False, nullable = False)
  authorSub = db.Column(db.String(50), unique = False, nullable = False) #at some point, one-to-many relationship must be established
  authors = db.Column(db.String(200), unique = False, nullable = False)
  affiliations = db.Column(db.String(150), unique = False, nullable = False)
  appyterInstance = db.Column(db.VARCHAR(1700), unique = True, nullable = False) #URL
  originalAppyter = db.Column(db.VARCHAR(1700), unique = True, nullable = False) #URL
  dateCreated = db.Column(db.Date, unique = False, nullable = False)
  references = db.Column(db.String(200), unique = False, nullable = False)
  keywords = db.Column(db.String(200), unique = False, nullable = False)
  dateApproved = db.Column(db.Date, unique = False, nullable = False)
  views = db.Column(db.Integer)
  citations = db.Column(db.Integer)
  saves = db.Column(db.Integer)
  shares = db.Column(db.Integer)
  def __init__(self, title, dateSub, authorSub, authors, affiliations, appyterInstance, originalAppyter, dateCreated, references, keywords, dateApproved, views, citations, saves, shares):
    self.title = title
    self.dateSub = dateSub
    self.authorSub = authorSub
    self.authors = authors
    self.affiliations = affiliations 
    self.appyterInstance = appyterInstance
    self.originalAppyter = originalAppyter
    self.dateCreated = dateCreated
    self.references = references
    self.keywords = keywords
    self.dateApproved = dateApproved
    self.views = views
    self.citations = citations
    self.saves = saves
    self.shares = shares

  def __repr__(self):
        return '<ApprovedInstance %r>' % self.title



class Role(db.Model):
  __bind_key__ = 'role'
  id = db.Column(db.Integer, primary_key = True)
  name = db.Column(db.String(40))
  description = db.Column(db.String(255))
  #many to many relationship between Users and Role)


class InstanceForm(FlaskForm):
    id_field = HiddenField()
    title = StringField('Appyter Name',[ InputRequired(), Regexp(r'^[A-Za-z\s\-\']+$', message="Invalid title"), Length(min=3, max = 100, message="invalid title length")])
    dateSub = HiddenField()
    authorSub = StringField("Name of Submission Author",[ InputRequired(), Regexp(r'^[A-Za-z\s\-\']+$', message="Invalid author name"), Length(min=3, max = 50, message="Invalid author name length")])
    authors = StringField("Names of all contributing authors, separated by commas", [ Regexp(r'^[A-Za-z\s\-\']+$', message="Invalid author name(s)"), Length(min=3, max = 200, message="invalid author name(s) length")])
    affiliations = StringField("Name of all affiliated instutions, separated by commas")
    appyterInstance = StringField("URL for the Instance", [InputRequired(), URL()])
    originalAppyter = StringField("URL for the Original Appyter", [InputRequired(), URL()])
    dateCreated = DateField("Date Appyter was run", [InputRequired()])
    references = StringField("Citations, separated by commas", [InputRequired(), Regexp(r'^[A-Za-z\s\-\']+$', message="Invalid references"), Length(min=3, max = 200, message="Invalid references length")])
    keywords = StringField("Search keywords, separated by commas", [InputRequired(), Regexp(r'^[A-Za-z\s\-\']+$', message="Invalid references"), Length(min=3, max = 200, message="Invalid references length")])
    submit = SubmitField('Submit')

def stringdate():
    today = date.today()
    date_list = str(today).split('-')
    # build string in format 01-01-2000
    date_string = date_list[1] + "-" + date_list[2] + "-" + date_list[0]
    return date_string

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)
admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))
admin_role = Role(name='admin')
db.session.commit()

###ROUTES###

@app.route(ROOT_PATH + 'static')
def staticfiles(path):
  return flask.send_from_directory('static', path)

@app.route(ROOT_PATH, methods=['GET', 'POST'])
def index():
  user1 = User(email='eslobode@andrew.cmu.edu', password=generate_password_hash('maayan1234', method = 'sha256'),  name='Emily Slobodenyuk')
  role1= Role(name='admin', description='Administrative role')
  user1.roles.append(role1)
  db.session.add(user1)
  db.session.commit()
  return flask.render_template('index.html')

@app.route(ROOT_PATH + 'submission_portal', methods=['GET', 'POST'])
def submissionPortal():
  form1 = InstanceForm()
  if form1.validate_on_submit():
    title = request.form['title']
    dateSub = datetime.strptime(stringdate(), "%d-%m-%Y")
    authorSub = request.form['authorSub']
    authors = request.form['authors']
    affiliations = request.form['affiliations']
    appyterInstance = request.form['appyterInstance']
    originalAppyter = request.form['originalAppyter']
    inputDateCreated = request.form['dateCreated']
    dateCreated = datetime.strptime(inputDateCreated, "%Y-%m-%d")
    references = request.form['references']
    keywords = request.form['keywords']
    record = AppyterInstances(title, dateSub, authorSub, authors, affiliations, appyterInstance, originalAppyter, dateCreated, references, keywords)
    db.session.add(record)
    db.session.commit()
    print("success!")
    message = f"The data for the Appyter Instance entitled {title} has been submitted"
    return render_template('submission.html', message = message)
  else:
        # show validaton errors
        # see https://pythonprogramming.net/flash-flask-tutorial/
        for field, errors in form1.errors.items():
            for error in errors:
                flash("Error in {}: {}".format(
                    getattr(form1, field).label.text,
                    error
                ), 'error')
        message = "yoinks"
        return render_template('submission.html', form1=form1)

@app.route(ROOT_PATH + 'about')
def about():
  return render_template('about.html')

@app.route(ROOT_PATH + 'login')
def login():
  return render_template('login.html')

@app.route(ROOT_PATH + 'signup')
def signup():
  return render_template('signup.html')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = 'login'
###


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route(ROOT_PATH + 'signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()
   
    print(user)
    if user:
      return render_template('signup.html', message= "This email has already been registered!")
    newUser = User(email, generate_password_hash(password, method = 'sha256'), name)
    newUser.roles.append('user')
    db.session.add(newUser)
    db.session.commit()
    print("SUCCESSS")
    return render_template('login.html')

@app.route(ROOT_PATH + 'login', methods=['POST'])
def login_post():
  email = request.form.get('email')
  password = request.form.get('password')
  remember = True if request.form.get('remember') else False

  user = User.query.filter_by(email=email).first()
  if not user or not check_password_hash(user.password, password):
    return render_template('login.html', message = 'Please check you login credentials and try again')
  login_user(user, remember = remember)
  return render_template('profiles.html')

@app.route(ROOT_PATH + 'profile')
@login_required
def profile():
  return render_template('profiles.html', name = current_user.name, role = current_user.role)

@app.route(ROOT_PATH + 'logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('index'))