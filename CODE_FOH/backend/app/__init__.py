from flask import Flask
from flask_cors import CORS
import os
from dotenv import load_dotenv
from datetime import timedelta
from flask_apscheduler import APScheduler

scheduler = APScheduler()


def create_app():
    app = Flask(__name__)
    app.config['SCHEDULER_API_ENABLED'] = True
    app.config['APSCHEDULER_TIMEZONE'] = 'UTC'  # Set appropriate timezone
    app.config['TESTING'] = True
    # Load environment variables from .env file
    load_dotenv()

    # Enable CORS for requests from the frontend on port 5001
    CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5001"])

    # App configurations
    app.config['DATABASE'] = 'test_database.db' if app.config.get(
        # Add a testing mode for unit test of create_user - UNIT TEST ADDITION
        "TESTING") else 'database.db'
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

    # Initialize database
    from .db import init_app
    init_app(app)

    # Register blueprints
    from .controllers.user_controller import user_bp
    from .controllers.log_controller import log_bp
    from .controllers.stock_controller import stock_bp
    from .controllers.transaction_controller import transaction_bp
    app.register_blueprint(user_bp, url_prefix='/api/user')
    app.register_blueprint(log_bp, url_prefix='/api/log')
    app.register_blueprint(stock_bp, url_prefix='/api/stock')
    app.register_blueprint(transaction_bp, url_prefix='/api/transaction')

    # Initialize scheduler only if not in testing mode - UNIT TEST ADDITION
    if not app.config.get("TESTING", False):
        scheduler.init_app(app)
        scheduler.start()

    return app
