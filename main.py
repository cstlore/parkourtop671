import datetime
import os
import time
from random import randint

from flask import Flask, render_template, redirect, request, jsonify
from flask_login import LoginManager, login_manager, login_user, current_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.fields.simple import EmailField
from wtforms.validators import DataRequired
from data import db_session
from data.users import User
from data.posts import Post
import bcrypt
import smtplib
from email.mime.text import MIMEText
from flask import session

UPLOAD_FOLDER = './static/upload'
app = Flask(__name__, static_folder="static")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = b'_53oi3uriq9pifpff;apl'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(
    days=365
)
login_manager = LoginManager()  ######
login_manager.init_app(app)


#
@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


# s
class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    email_ = EmailField('Почта', validators=[DataRequired()])
    password_ = PasswordField('Пароль', validators=[DataRequired()])
    submit_ = SubmitField('Зарегистрироваться')


#
@app.route('/auth', methods=['GET', 'POST'])
def auth():
    # login_form
    login_form = LoginForm()
    register_form = RegisterForm()
    if login_form.submit.data and login_form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == login_form.email.data).first()
        db_sess.close()
        if user and user.check_password(login_form.password.data):
            login_user(user, remember=login_form.remember_me.data)
            return redirect('/')
        if user and user.check_password(login_form.password.data) is False:
            return render_template('login.html',
                                   login_message="Неправильный логин или пароль",
                                   register_message='',
                                   login_form=login_form, register_form=register_form)
    # register_form
    if register_form.submit_.data and register_form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == register_form.email_.data).first()
        if user:
            return render_template('login.html',
                                   login_message='',
                                   register_message="Такой пользователь уже существует",
                                   login_form=login_form, register_form=register_form)
        new_user = User()
        new_user.email = register_form.email_.data
        password = register_form.password_.data
        bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(bytes, salt)
        new_user.hashed_password = hashed
        db_sess.add(new_user)
        db_sess.commit()
        db_sess.close()
    return render_template('login.html', title='Авторизация', login_form=login_form, register_form=register_form)


######
@app.route('/add_profile', methods=['GET', 'POST'])
def add_profile():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    if request.method == 'POST':
        if 'file1' not in request.files:
            return 'there is no file1 in form!'
        file1 = request.files['file1']
        path = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
        file1.save(path)
        db_sess = db_session.create_session()
        new_post = Post()
        new_post.email = current_user.email
        new_post.image = path
        db_sess.add(new_post)
        db_sess.commit()
        db_sess.close()
        return redirect('/')
    return render_template('profile.html')


################################№№################
#####
@app.route('/contact/<email>', methods=['POST'])
def contact(email):
    text = MIMEText(f'Пользователю:{current_user.email} очень понравились вы, напишите ему прямо сейчас!!!', 'plain',
                    'utf-8')
    smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    smtpObj.starttls()
    smtpObj.login('c93314903@gmail.com', 'rxiy lquq bdgn wkmc')
    smtpObj.sendmail("c93314903@gmail.com", email, text.as_string())
    return jsonify(result='ok')


#
############
@app.route('/')
def render():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    return render_template('page.html', files=files)


##########

########

#####№###############
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


k = 0


###


@app.route('/kluet', methods=["GET", "POST"])
def kluet():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    if request.method == "POST":
        time.sleep(randint(1, 10))
        return render_template("kluet.html", files=files)


@app.route('/process', methods=["GET", "POST"])
def process():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    global k
    k += 1
    return render_template("process.html", k=k, files=files)


@app.route('/game', methods=["GET", "POST"])
def game():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    return render_template("game.html", files=files)
##########
#############
@app.route('/poimal', methods=["GET", "POST"])
def poimal():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    return render_template("poimal.html", files=files)


@app.route('/itog', methods=["GET", "POST"])
def fish():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    k = randint(0, 9)
    jpg = ['amur.jpg', 'forel.jpg', 'gorbusha.jpg', 'karas.jpg', 'karp.jpg', 'lesch.jpg', 'lin.jpg', 'okun.jpg',
           'sudak.jpg', 'yaz.jpg']
    return render_template("fish.html", picture=jpg[k], files=files)


@app.route('/vozvrat', methods=["GET", "POST"])
def vozvrat():
    if current_user.is_authenticated is False:
        return redirect('/auth')
    files = os.listdir('./static/upload')
    files = list(files)
    db_sess = db_session.create_session()
    for i in range(len(files)):
        files[i] = (files[i], db_sess.query(Post).filter(Post.image == f'./static/upload\\{files[i]}').first().email)
    db_sess.close()
    return render_template("start.html", files=files)

########
###############################################
###
def main():
    db_session.global_init('db/users.sqlite')  # №№####
    app.run(port=8080, host='127.0.0.1')


################
####
#
if __name__ == '__main__':
    main()
