from flask import Flask, render_template
from models import db, User
from flask_migrate import Migrate
import os
from flask_jwt_extended import JWTManager
from blueprints.auth import auth_bp

app = Flask(__name__)
# Use a relative path for SQLite database
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'db.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Initialize the database and migrations
migrate = Migrate(app, db)
db.init_app(app)

# Initialize JWT
jwt = JWTManager(app)

# Register the authentication blueprint
app.register_blueprint(auth_bp)

# Error handler for JWT unauthorized access
@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({'message': 'Unauthorized access'}), 401


if __name__ == '__main__':
    # Create the database tables before running the app
    with app.app_context():
        db.create_all()
    app.run(debug=True)
