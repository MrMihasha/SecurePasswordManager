"""
Secure Password Manager - by https://github.com/MrMihasha
"""
from app import create_app, db
from app.models import User, Password

app = create_app()

@app.shell_context_processor
def make_shell_context():
    """Make database models available in Flask shell"""
    return {'db': db, 'User': User, 'Password': Password}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Use HTTPS in production with proper SSL certificates
    app.run(host='0.0.0.0', port=8080, debug=False)
