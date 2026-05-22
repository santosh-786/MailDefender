import pytest
from app import create_app, db
from app.models import EmailAnalysis

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_dashboard_access(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"SOC Analyst Dashboard" in response.data

def test_upload_page_access(client):
    response = client.get('/upload')
    assert response.status_code == 200
    assert b"Analyze New Email" in response.data

def test_raw_header_analysis(client):
    raw_email = "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nBody content with http://phish.com"
    response = client.post('/upload', data={'raw_headers': raw_email}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Investigation" in response.data
    # In Scoring Engine V2, we might not render the sender directly in the same way
    # Let's check for "Risk Score" or "Trust Score"
    assert b"Risk Score" in response.data
    assert b"Trust Score" in response.data
