import sys
from pathlib import Path

# Добавляем корневую папку проекта в путь поиска модулей Python.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import os
from datetime import date

# Изолируем тесты от рабочей базы данных PostgreSQL.
os.environ["DATABASE_URL"] = "sqlite://"

import pytest

# Подключаем приложение, базу данных и модели для тестирования.
from app import app, db, User, Incident, Person, IncidentPerson


# Создание тестового клиента и подготовка тестовой базы данных.
@pytest.fixture()
def client():
    """Создаёт чистую тестовую базу перед каждым тестом."""
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        WTF_CSRF_ENABLED=False,
    )

    with app.app_context():
        db.drop_all()
        db.create_all()

        test_client = app.test_client()
        yield test_client

        db.session.remove()
        db.drop_all()


# Функция для добавления тестового пользователя в базу данных.
def add_user(login="operator_test", password="test1234", role="operator"):
    user = User(login=login, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


# Функция для выполнения авторизации через форму приложения.
def login(client, login_name="operator_test", password="test1234"):
    return client.post(
        "/login",
        data={"login": login_name, "password": password},
        follow_redirects=False,
    )


# Подготовка тестовых данных для создания происшествия.
def incident_data(registration_number="INC-TEST-001"):
    return {
        "registration_number": registration_number,
        "registration_date": "2025-05-15",
        "description": "Тестовое описание происшествия",
        "incident_type": "кража",
        "decision_type": "",
        "case_number": "",
    }


# Подготовка тестовых данных для создания информации о лице.
def person_data(registration_number="PER-TEST-001"):
    return {
        "registration_number": registration_number,
        "last_name": "Иванов",
        "first_name": "Иван",
        "middle_name": "Иванович",
        "address": "Тестовый адрес",
        "convictions_count": "0",
    }


# unit-тесты

# 1-я проверка: проверка хеширования пароля и его последующей проверки.
def test_password_is_hashed_and_verified():
    user = User(login="unit_user", role="user")
    user.set_password("secret123")

    assert user.password_hash != "secret123"
    assert user.check_password("secret123") is True
    assert user.check_password("wrong-password") is False

# Интеграционные тесты

# 2-я проверка: проверка прохождения авторизации с правильным логином и паролем.
def test_login_with_correct_credentials(client):
    add_user()
    response = login(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


# 3-я проверка: проверка отказа в авторизации при неправильном пароле.
def test_login_with_incorrect_password(client):
    add_user()
    response = login(client, password="wrong-password")

    assert response.status_code == 200


# 4-я проверка: проверка перенаправления неавторизованного пользователя на страницу входа.
def test_guest_is_redirected_to_login(client):
    response = client.get("/incidents")

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


# 5-я проверка: проверка запрета добавления происшествия пользователем с ролью user.
def test_user_role_cannot_add_incident(client):
    add_user(login="viewer_test", role="user")
    login(client, login_name="viewer_test")

    response = client.post("/incidents/add", data=incident_data())

    assert response.status_code == 403
    assert Incident.query.count() == 0


# 6-я проверка: проверка успешного добавления нового происшествия оператором.
def test_operator_can_add_incident(client):
    add_user()
    login(client)

    response = client.post("/incidents/add", data=incident_data())

    assert response.status_code == 302
    assert Incident.query.filter_by(
        registration_number="INC-TEST-001"
    ).first() is not None


# 7-я проверка: проверка запрета добавления происшествия с повторяющимся регистрационным номером.
def test_duplicate_incident_registration_number_is_rejected(client):
    add_user()
    login(client)

    first_response = client.post("/incidents/add", data=incident_data())
    second_response = client.post("/incidents/add", data=incident_data())

    assert first_response.status_code == 302
    assert second_response.status_code == 200
    assert Incident.query.filter_by(
        registration_number="INC-TEST-001"
    ).count() == 1


# 8-я проверка: проверка обязательного указания номера дела для решения approved.
def test_approved_decision_requires_case_number(client):
    add_user()
    login(client)

    data = incident_data("INC-TEST-002")
    data["decision_type"] = "approved"
    data["case_number"] = ""

    response = client.post("/incidents/add", data=data)

    assert response.status_code == 200
    assert Incident.query.filter_by(
        registration_number="INC-TEST-002"
    ).first() is None


# 9-я проверка: проверка успешного добавления нового лица оператором.
def test_operator_can_add_person(client):
    add_user()
    login(client)

    response = client.post("/persons/add", data=person_data())

    assert response.status_code == 302
    assert Person.query.filter_by(
        registration_number="PER-TEST-001"
    ).first() is not None


# 10-я проверка: проверка запрета ввода отрицательного количества судимостей.
def test_negative_convictions_count_is_rejected(client):
    add_user()
    login(client)

    data = person_data("PER-TEST-002")
    data["convictions_count"] = "-1"

    response = client.post("/persons/add", data=data)

    assert response.status_code == 200
    assert Person.query.filter_by(
        registration_number="PER-TEST-002"
    ).first() is None


# 11-я проверка: проверка успешного создания связи между лицом и происшествием.
def test_operator_can_link_person_to_incident(client):
    add_user()
    incident = Incident(
        registration_number="INC-LINK-001",
        registration_date=date(2025, 5, 15),
        description="Происшествие для проверки связи",
        incident_type="кража",
    )
    person = Person(
        registration_number="PER-LINK-001",
        last_name="Петров",
        first_name="Пётр",
        address="Тестовый адрес",
        convictions_count=0,
    )
    db.session.add_all([incident, person])
    db.session.commit()

    login(client)
    response = client.post(
        "/links",
        data={
            "incident_id": str(incident.incident_id),
            "person_id": str(person.person_id),
            "role": "свидетель",
        },
    )

    assert response.status_code == 302
    assert IncidentPerson.query.filter_by(
        incident_id=incident.incident_id,
        person_id=person.person_id,
    ).first() is not None


# 12-я проверка: проверка запрета создания связи между лицом и происшествием пользователем с ролью user.
def test_viewer_cannot_create_person_incident_link(client):
    add_user(login="viewer_test", role="user")
    incident = Incident(
        registration_number="INC-LINK-002",
        registration_date=date(2025, 5, 15),
        description="Происшествие для проверки прав",
        incident_type="кража",
    )
    person = Person(
        registration_number="PER-LINK-002",
        last_name="Сидоров",
        first_name="Сидор",
        address="Тестовый адрес",
        convictions_count=0,
    )
    db.session.add_all([incident, person])
    db.session.commit()

    login(client, login_name="viewer_test")
    response = client.post(
        "/links",
        data={
            "incident_id": str(incident.incident_id),
            "person_id": str(person.person_id),
            "role": "свидетель",
        },
    )

    assert response.status_code == 302
    assert IncidentPerson.query.count() == 0
