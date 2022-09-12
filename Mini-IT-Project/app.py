#__init__-___________________________________________________________________________
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'd6ffbab446362ecdef29c8fa'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///courses.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

    
#Models______________________________________________________________________________
user_class = db.Table('user_class',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('class_id', db.Integer, db.ForeignKey('class.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(length=50), nullable=False, unique=True)
    name = db.Column(db.String(length=30), nullable=False)
    password1 = db.Column(db.String(length=100), nullable=False)
    budget = db.Column(db.Integer(), nullable=False, default=500)
    classes = db.relationship('Class', secondary=user_class, backref='students', lazy=True)
    
    @property
    def prettier_budget(self):
        if len(str(self.budget)) >= 4:
            return f'RM{str(self.budget)[:-3]},{str(self.budget)[-3:]}'
        else:
            return f"RM{self.budget}"

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password1 = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password1, attempted_password)

    def can_purchase(self, item_obj):
        return self.budget >= item_obj.price

class Class(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=30), nullable=False, unique=True)
    description = db.Column(db.String(length=1024), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    capacity = db.Column(db.Integer, default=5) 
    num_student = db.Column(db.Integer(), default=0)
    
    def __repr__(self):
        return f'Class: {self.name}'

    def buy(self, user):
        self.user_id = user.id
        user.budget -= self.price
        self.num_student += 1
        user.classes.append(self) #need to be adjusted later
        db.session.commit()
#Models______________________________________________________________________________


#Forms_______________________________________________________________________________
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError

class Register(FlaskForm):
    def validate_email(self, email_to_check):
        email = User.query.filter_by(email=email_to_check.data).first()
        if email:
            raise ValidationError('Email Address already exists!')

    email = StringField(label='Email Address :',validators=[Email(), DataRequired()])
    name = StringField(label='User Name :',validators=[Length(min=3, max=50), DataRequired()])
    password1 = PasswordField(label='Password :',validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password :', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')

class Login(FlaskForm):
    email = StringField(label='Email Address :',validators=[DataRequired()])
    password = PasswordField(label='Password :',validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class Add(FlaskForm):
    def validate_name(self, name_to_check):
        name = Class.query.filter_by(name=name_to_check.data).first()
        if name:
            raise ValidationError('Course already exists!')

    name = StringField(label='Name of Game :',validators=[Length(min=3, max=50),DataRequired()])
    price = IntegerField(label='Price :',validators=[DataRequired()])
    description = StringField(label='Description :',validators=[Length(max=500),DataRequired()])
    submit = SubmitField(label='Add Course')


class PurchaseCourseForm(FlaskForm):
    submit = SubmitField(label='Purchase Courses!')

#class SellCourseForm(FlaskForm):
#    submit = SubmitField(label='Sell Courses!')
#Formss______________________________________________________________________________


#Routes______________________________________________________________________________
@app.route('/')
@app.route('/home')
def home() :
    return render_template("home.html")

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    form = Register()
    if form.validate_on_submit():
        user_to_create = User(email=form.email.data, name=form.name.data, password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f'Account created successfully! You are now logged in as {user_to_create.name}', category='success')
        return redirect(url_for('courses'))
    if form.errors != {}: #If there are not errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')
    return render_template("sign_up.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(email=form.email.data).first()
        if attempted_user and attempted_user.check_password_correction(attempted_password=form.password.data):
            login_user(attempted_user)
            if attempted_user.email == "admin@gmail.com": #need to change validation using email
                flash(f'Success! You are logged in as: {attempted_user.name}', category='success')
                return redirect(url_for('admin_view'))
            elif attempted_user.email != "admin@gmail.com": #need to change validation using email
                flash(f'Success! You are logged in as: {attempted_user.name}', category='success')
                return redirect(url_for('courses'))
            else:
                flash('Email Address and password do not match!', category='danger')
    return render_template("login.html", form=form)

@app.route('/courses', methods=['GET', 'POST'])
@login_required
def courses():
    purchase_form = PurchaseCourseForm()
    if request.method == "POST":
        purchased_class = request.form.get('purchased_class')
        p_class_object = Class.query.filter_by(name=purchased_class).first()
        if p_class_object:
            if current_user.can_purchase(p_class_object):
                if p_class_object.capacity > p_class_object.num_student: #capacity checking
                    p_class_object.buy(current_user)
                    flash(f"Thank you for joining our {p_class_object.name} for RM{p_class_object.price}", category='success')
                else:
                    flash(f"Unfortunately, {p_class_object.name} course is already full!", category='danger')
            else:
                flash(f"Unfortunately, you don't have enough money to purchase {p_class_object.name}!", category='danger')
        return redirect(url_for('courses'))
    if request.method == "GET":
        #need to add/ change "student" something if necessory
        classes = Class.query.filter_by(capacity=5)
    return render_template("courses.html", classes=classes, purchase_form=purchase_form)

# 
@app.route('/courses_to_add', methods=['GET', 'POST'])
@login_required
def admin_view():
    purchase_form = PurchaseCourseForm()
    if request.method == "GET":
        #need to add something if necessory
        classes = Class.query.filter_by(capacity=5)
    return render_template("admin_view.html", classes=classes, purchase_form=purchase_form)


@app.route('/{current_user.name} ')
def user():
    return render_template("user.html")

@app.route('/ADMIN ', methods=['GET', 'POST'])
def admin():
    if request.method == "GET":
        #need to add something if necessory
        classes = Class.query.all()
        order = Class.query.order_by(Class.num_student.desc()).all()
    return render_template("admin.html", classes=classes, order=order)

@app.route('/Add Courses', methods=['GET', 'POST'])
def add_courses():
    form = Add()
    if form.validate_on_submit():
        course_to_create = Class(name=form.name.data, price=form.price.data, description=form.description.data)
        db.session.add(course_to_create)
        db.session.commit()
        flash(f'Course created successfully! {course_to_create.name} was added to the Class list', category='success')
        return redirect(url_for('admin_view'))
    if form.errors != {}: #If there are not errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a course: {err_msg}', category='danger')
    return render_template("add_courses.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out", category='info')
    return redirect(url_for('home'))
#Routes______________________________________________________________________________

if __name__ == '__main__':
    app.run(debug=True)