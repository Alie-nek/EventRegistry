import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField, IntegerField, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, NumberRange, Optional
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import InputRequired

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Требуется авторизация.'

# ==================== МОДЕЛИ ====================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), nullable=False, default='user')

    def get_id(self):
        return str(self.user_id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Incident(db.Model):
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    registration_number = db.Column(db.String(64), unique=True, nullable=False)
    registration_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=False)
    incident_type = db.Column(db.String(128), nullable=False)

    decision = db.relationship('Decision', backref='incident', uselist=False, cascade='all, delete-orphan')
    participations = db.relationship('IncidentPerson', backref='incident', cascade='all, delete-orphan')


class Decision(db.Model):
    __tablename__ = 'decisions'
    decision_id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.incident_id'), unique=True, nullable=False)
    decision_type = db.Column(db.String(64), nullable=False)
    case_number = db.Column(db.String(64), nullable=True)


class Person(db.Model):
    __tablename__ = 'persons'
    person_id = db.Column(db.Integer, primary_key=True)
    registration_number = db.Column(db.String(64), unique=True, nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    first_name = db.Column(db.String(64), nullable=False)
    middle_name = db.Column(db.String(64), nullable=True)
    address = db.Column(db.String(256), nullable=False)
    convictions_count = db.Column(db.Integer, nullable=False, default=0)

    participations = db.relationship('IncidentPerson', backref='person', cascade='all, delete-orphan')


class IncidentPerson(db.Model):
    __tablename__ = 'incident_persons'
    participation_id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.incident_id'), nullable=False)
    person_id = db.Column(db.Integer, db.ForeignKey('persons.person_id'), nullable=False)
    role = db.Column(db.String(64), nullable=False)

    __table_args__ = (db.UniqueConstraint('incident_id', 'person_id', name='uq_incident_person'),)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ==================== ИСКЛЮЧЕНИЯ ====================

class DuplicateRegistrationNumberException(Exception):
    pass

class NegativeConvictionsException(Exception):
    pass

class DecisionWithoutCaseNumberException(Exception):
    pass

class InvalidDateRangeException(Exception):
    pass


# ==================== ФОРМЫ ====================

class LoginForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class IncidentForm(FlaskForm):
    registration_number = StringField('Регистрационный номер', validators=[DataRequired(), Length(max=64)])
    registration_date = DateField('Дата регистрации', validators=[DataRequired()])
    description = TextAreaField('Краткая фабула', validators=[DataRequired()])
    incident_type = SelectField('Тип происшествия', choices=[
    ('кража', 'Кража'),
    ('грабеж', 'Грабёж'),
    ('разбой', 'Разбой'),
    ('мошенничество', 'Мошенничество'),
    ('хулиганство', 'Хулиганство'),
    ('дтп', 'ДТП'),
    ('пожар', 'Пожар'),
    ('иное', 'Иное'),
], validators=[DataRequired()])
    decision_type = SelectField('Решение', 
        id='decision_type',  
        choices=[
            ('', '— не выбрано —'),
            ('refused', 'Отказано в возбуждении уголовного дела'),
            ('approved', 'Удовлетворено ходатайство о возбуждении уголовного дела'),
            ('territorial', 'Материал направлен по территориальному признаку'),
        ], validators=[Optional()])
    case_number = StringField('Номер заведённого дела', validators=[Optional(), Length(max=64)])
    submit = SubmitField('Сохранить')


class PersonForm(FlaskForm):
    registration_number = StringField('Регистрационный номер', validators=[DataRequired(), Length(max=64)])
    last_name = StringField('Фамилия', validators=[DataRequired(), Length(max=64)])
    first_name = StringField('Имя', validators=[DataRequired(), Length(max=64)])
    middle_name = StringField('Отчество', validators=[Optional(), Length(max=64)])
    address = StringField('Адрес', validators=[DataRequired(), Length(max=256)])
    convictions_count = IntegerField('Количество судимостей', validators=[InputRequired(), NumberRange(min=0)])
    submit = SubmitField('Сохранить')


class LinkForm(FlaskForm):
    incident_id = SelectField('Происшествие', coerce=int, validators=[DataRequired()])
    person_id = SelectField('Лицо', coerce=int, validators=[DataRequired()])
    role = SelectField('Роль', choices=[
        ('виновник', 'Виновник'),
        ('потерпевший', 'Потерпевший'),
        ('подозреваемый', 'Подозреваемый'),
        ('свидетель', 'Свидетель'),
        ('иное', 'Иное'),
    ], validators=[DataRequired()])
    submit = SubmitField('Связать')


class StatsPeriodForm(FlaskForm):
    start_date = DateField('Начальная дата', validators=[DataRequired()])
    end_date = DateField('Конечная дата', validators=[DataRequired()])
    submit = SubmitField('Рассчитать')


class StatsPersonForm(FlaskForm):
    person_id = SelectField('Лицо', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Рассчитать')


class UserForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Пароль', validators=[Optional(), Length(min=4)])
    role = SelectField('Роль', choices=[
        ('operator', 'Оператор'),
        ('user', 'Пользователь (просмотр)'),
        ('admin', 'Администратор'),
    ])
    submit = SubmitField('Сохранить')


# ==================== ДЕКОРАТОРЫ ====================

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def operator_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'operator':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def viewer_allowed(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ('operator', 'user'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ==================== МАРШРУТЫ ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login=form.login.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Вы вошли в систему.', 'success')
            return redirect(url_for('index'))
        flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    if current_user.role == 'admin':
        return redirect(url_for('admin_users'))
    incident_count = Incident.query.count()
    person_count = Person.query.count()
    return render_template('index.html', incident_count=incident_count, person_count=person_count)


# ---------- Происшествия ----------

@app.route('/incidents')
@login_required
@viewer_allowed
def incidents():
    items = Incident.query.order_by(Incident.registration_date.desc()).all()
    return render_template('incidents.html', incidents=items)


@app.route('/incidents/add', methods=['GET', 'POST'])
@login_required
@operator_only
def incident_add():
    form = IncidentForm()
    if form.validate_on_submit():
        try:
            if Incident.query.filter_by(registration_number=form.registration_number.data).first():
                raise DuplicateRegistrationNumberException()
            if form.decision_type.data == 'approved' and not form.case_number.data:
                raise DecisionWithoutCaseNumberException()

            inc = Incident(
                registration_number=form.registration_number.data,
                registration_date=form.registration_date.data,
                description=form.description.data,
                incident_type=form.incident_type.data,
            )
            db.session.add(inc)
            db.session.flush()

            if form.decision_type.data:
                db.session.add(Decision(
                    incident_id=inc.incident_id,
                    decision_type=form.decision_type.data,
                    case_number=form.case_number.data if form.decision_type.data == 'approved' else None,
                ))

            db.session.commit()
            flash('Происшествие добавлено.', 'success')
            return redirect(url_for('incidents'))

        except DuplicateRegistrationNumberException:
            flash('Происшествие с таким регистрационным номером уже существует.', 'danger')
        except DecisionWithoutCaseNumberException:
            flash('Для решения о возбуждении дела необходимо указать номер дела.', 'danger')

    return render_template('incident_form.html', form=form, title='Добавить происшествие')


@app.route('/incidents/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@operator_only
def incident_edit(id):
    inc = Incident.query.get_or_404(id)
    form = IncidentForm(obj=inc)

    if request.method == 'GET' and inc.decision:
        form.decision_type.data = inc.decision.decision_type
        form.case_number.data = inc.decision.case_number

    if form.validate_on_submit():
        try:
            if form.decision_type.data == 'approved' and not form.case_number.data:
                raise DecisionWithoutCaseNumberException()

            inc.registration_number = form.registration_number.data
            inc.registration_date = form.registration_date.data
            inc.description = form.description.data
            inc.incident_type = form.incident_type.data

            if inc.decision:
                inc.decision.decision_type = form.decision_type.data
                inc.decision.case_number = form.case_number.data if form.decision_type.data == 'approved' else None
            elif form.decision_type.data:
                db.session.add(Decision(
                    incident_id=inc.incident_id,
                    decision_type=form.decision_type.data,
                    case_number=form.case_number.data if form.decision_type.data == 'approved' else None,
                ))

            db.session.commit()
            flash('Происшествие обновлено.', 'success')
            return redirect(url_for('incidents'))

        except DecisionWithoutCaseNumberException:
            flash('Для решения о возбуждении дела необходимо указать номер дела.', 'danger')

    return render_template('incident_form.html', form=form, title='Редактировать происшествие')


@app.route('/incidents/delete/<int:id>', methods=['POST'])
@login_required
@operator_only
def incident_delete(id):
    inc = Incident.query.get_or_404(id)
    db.session.delete(inc)
    db.session.commit()
    flash('Происшествие удалено.', 'info')
    return redirect(url_for('incidents'))


# ---------- Лица ----------

@app.route('/persons')
@login_required
@viewer_allowed
def persons():
    items = Person.query.order_by(Person.last_name).all()
    return render_template('persons.html', persons=items)


@app.route('/persons/add', methods=['GET', 'POST'])
@login_required
@operator_only
def person_add():
    form = PersonForm()
    if form.validate_on_submit():
        try:
            if Person.query.filter_by(registration_number=form.registration_number.data).first():
                raise DuplicateRegistrationNumberException()
            if form.convictions_count.data < 0:
                raise NegativeConvictionsException()

            p = Person(
                registration_number=form.registration_number.data,
                last_name=form.last_name.data,
                first_name=form.first_name.data,
                middle_name=form.middle_name.data,
                address=form.address.data,
                convictions_count=form.convictions_count.data,
            )
            db.session.add(p)
            db.session.commit()
            flash('Лицо добавлено.', 'success')
            return redirect(url_for('persons'))

        except DuplicateRegistrationNumberException:
            flash('Лицо с таким регистрационным номером уже существует.', 'danger')
        except NegativeConvictionsException:
            flash('Количество судимостей не может быть отрицательным.', 'danger')

    return render_template('person_form.html', form=form, title='Добавить лицо')


@app.route('/persons/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@operator_only
def person_edit(id):
    p = Person.query.get_or_404(id)
    form = PersonForm(obj=p)
    if form.validate_on_submit():
        try:
            if form.convictions_count.data < 0:
                raise NegativeConvictionsException()

            p.registration_number = form.registration_number.data
            p.last_name = form.last_name.data
            p.first_name = form.first_name.data
            p.middle_name = form.middle_name.data
            p.address = form.address.data
            p.convictions_count = form.convictions_count.data
            db.session.commit()
            flash('Данные лица обновлены.', 'success')
            return redirect(url_for('persons'))

        except NegativeConvictionsException:
            flash('Количество судимостей не может быть отрицательным.', 'danger')

    return render_template('person_form.html', form=form, title='Редактировать лицо')


@app.route('/persons/delete/<int:id>', methods=['POST'])
@login_required
@operator_only
def person_delete(id):
    p = Person.query.get_or_404(id)
    db.session.delete(p)
    db.session.commit()
    flash('Лицо удалено.', 'info')
    return redirect(url_for('persons'))


# ---------- Связи ----------

@app.route('/links', methods=['GET', 'POST'])
@login_required
@viewer_allowed
def links():
    form = LinkForm()
    form.incident_id.choices = [(i.incident_id, f"{i.registration_number} — {i.description[:40]}") for i in Incident.query.all()]
    form.person_id.choices = [(p.person_id, f"{p.last_name} {p.first_name}") for p in Person.query.all()]

    if request.method == 'POST':
        if current_user.role != 'operator':
            flash('У вас нет прав на изменение данных.', 'danger')
            return redirect(url_for('links'))
        if form.validate_on_submit():
            existing = IncidentPerson.query.filter_by(
                incident_id=form.incident_id.data,
                person_id=form.person_id.data
            ).first()
            if existing:
                flash('Это лицо уже связано с данным происшествием.', 'warning')
            else:
                db.session.add(IncidentPerson(
                    incident_id=form.incident_id.data,
                    person_id=form.person_id.data,
                    role=form.role.data
                ))
                db.session.commit()
                flash('Связь добавлена.', 'success')
            return redirect(url_for('links'))

    all_links = IncidentPerson.query.all()
    return render_template('links.html', form=form, links=all_links)


@app.route('/links/delete/<int:id>', methods=['POST'])
@login_required
@operator_only
def link_delete(id):
    link = IncidentPerson.query.get_or_404(id)
    db.session.delete(link)
    db.session.commit()
    flash('Связь удалена.', 'info')
    return redirect(url_for('links'))


# ---------- Статистика ----------

@app.route('/stats', methods=['GET', 'POST'])
@login_required
@viewer_allowed
def stats():
    period_form = StatsPeriodForm()
    person_form = StatsPersonForm()
    person_form.person_id.choices = [(p.person_id, f"{p.last_name} {p.first_name}") for p in Person.query.all()]

    period_count = None
    person_count = None

    if period_form.validate_on_submit() and 'start_date' in request.form:
        try:
            if period_form.start_date.data > period_form.end_date.data:
                raise InvalidDateRangeException()
            period_count = Incident.query.filter(
                Incident.registration_date >= period_form.start_date.data,
                Incident.registration_date <= period_form.end_date.data
            ).count()
        except InvalidDateRangeException:
            flash('Начальная дата не может быть позже конечной.', 'danger')

    if person_form.validate_on_submit() and 'person_id' in request.form:
        person_count = IncidentPerson.query.filter_by(person_id=person_form.person_id.data).count()

    return render_template('stats.html',
                           period_form=period_form,
                           person_form=person_form,
                           period_count=period_count,
                           person_count=person_count)

@app.route('/persons/<int:id>')
@login_required
@viewer_allowed
def person_detail(id):
    person = Person.query.get_or_404(id)
    participations = IncidentPerson.query.filter_by(person_id=id).all()
    incidents = [p.incident for p in participations]
    return render_template('person_detail.html', person=person, incidents=incidents)
# ---------- Администрирование ----------

@app.route('/admin/users')
@login_required
@admin_only
def admin_users():
    users = User.query.all()
    form = UserForm()
    return render_template('admin_users.html', users=users, form=form)


@app.route('/admin/users/add', methods=['POST'])
@login_required
@admin_only
def admin_user_add():
    form = UserForm()
    if form.validate_on_submit():
        if User.query.filter_by(login=form.login.data).first():
            flash('Пользователь с таким логином уже существует.', 'danger')
        elif not form.password.data:
            flash('Пароль обязателен при создании пользователя.', 'danger')
        else:
            u = User(login=form.login.data, role=form.role.data)
            u.set_password(form.password.data)
            db.session.add(u)
            db.session.commit()
            flash('Пользователь добавлен.', 'success')
    else:
        flash('Ошибка в форме. Проверьте введённые данные.', 'danger')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
@admin_only
def admin_user_delete(id):
    u = User.query.get_or_404(id)
    if u.user_id == current_user.user_id:
        flash('Нельзя удалить самого себя.', 'warning')
    else:
        db.session.delete(u)
        db.session.commit()
        flash('Пользователь удалён.', 'info')
    return redirect(url_for('admin_users'))


# ==================== HEALTHCHECK ====================

@app.route('/health')
def health():
    return {'status': 'healthy', 'service': 'eventregistry'}, 200
    

# ==================== ЗАПУСК ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.first():
            for login, pwd, role in [
                ('admin', 'admin123', 'admin'),
                ('operator', 'operator123', 'operator'),
                ('user', 'user123', 'user'),
            ]:
                u = User(login=login, role=role)
                u.set_password(pwd)
                db.session.add(u)
            db.session.commit()
            print('Созданы пользователи: admin/admin123, operator/operator123, user/user123')

    app.run(debug=False, host='0.0.0.0', port=5000)
