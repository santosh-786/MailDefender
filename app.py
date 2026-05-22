from app import create_app, db

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # In production, use a WSGI server like gunicorn
    # For local analysis, we run on localhost
    app.run(host='127.0.0.1', port=5000, debug=False)
