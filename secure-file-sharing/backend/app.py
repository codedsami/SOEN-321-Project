from flask import Flask
from models import db
from auth import auth_bp

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_files.db'

db.init_app(app)
app.register_blueprint(auth_bp)

@app.route('/')
def index():
    return {'status': 'backend is running'}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)