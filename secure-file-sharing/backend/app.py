from flask import Flask
from flask_jwt_extended import JWTManager
from models import db
from routes.auth import auth_bp
from routes.files import files_bp
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_files.db'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db.init_app(app)
JWTManager(app)

app.register_blueprint(auth_bp)
app.register_blueprint(files_bp)

@app.route('/')
def index():
    return {'status': 'backend is running'}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)