import datetime
from flask import Flask, render_template, redirect
from flask_login import LoginManager, login_manager, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.fields.simple import EmailField
from wtforms.validators import DataRequired
from data import db_session
from data.users import User
import bcrypt
from flask import session

app = Flask(__name__)
app.secret_key = b'_53oi3uriq9pifpff;apl'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(
    days=365
)
login_manager = LoginManager()
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
    return render_template('login.html', title='Авторизация', login_form=login_form, register_form=register_form)


#

@app.route('/')
def render():
    return render_template('base.html')

######

def main():
    db_session.global_init('db/users.sqlite')
    app.run(port=8080, host='127.0.0.1')


if __name__ == '__main__':
    main()
