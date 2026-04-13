from flask import Flask, send_from_directory, redirect
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

# ── Serve frontend ────────────────────────────────────────────
FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'frontend')
)

@app.route('/')
def root():
    return redirect('/ui/index.html')

@app.route('/ui', defaults={'filename': 'index.html'})
@app.route('/ui/<path:filename>')
def serve_frontend(filename):
    return send_from_directory(FRONTEND_DIR, filename)
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)