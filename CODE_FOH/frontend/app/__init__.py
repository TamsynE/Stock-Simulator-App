from flask import Flask, render_template, session
from dotenv import load_dotenv  # Import load_dotenvtoc


def create_app():
    app = Flask(__name__)

    # Load environment variables from .env file
    load_dotenv()

    @app.route('/')
    @app.route("/register", methods=["GET", "POST"])
    def register():
        return render_template('register.html')

    @app.route("/login", methods=["GET", "POST"])
    def login():
        return render_template("login.html")

    @app.route("/index")
    def index():
        username = session.get("username")
        total_cash = session.get("totalCash", 0)  # Default to 0 if not set
        return render_template('index.html', username=username, totalCash=total_cash, active_page='portfolio')

    @app.route('/log')  # Adding the log route
    def log():
        return render_template('log.html', active_page='log')

    @app.route('/logout')  # Adding the logout route
    def logout():
        return render_template('logout.html')

    @app.route('/trade')  # Adding the trade route
    def trade():
        return render_template('trade.html', active_page='trade')

    @app.route('/admin')  # Corrected route for admin
    def admin():  # Renamed the function to avoid conflict
        return render_template('admin.html')

    @app.route('/visualization')  # Corrected route for visualization
    def visualization():  # Renamed the function to avoid conflict
        return render_template('visualization.html')
    return app
