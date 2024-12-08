from flask import Blueprint, jsonify, request, session, render_template
import datetime
from ..db import get_db
from datetime import datetime

log_bp = Blueprint('log', __name__)


@log_bp.route('/entries', methods=['GET'])
def get_log_entries():
    try:
        id = session.get("user_id")
        print(session)
        print("Fetching log entries...")  # Debugging print statement

        if not id:
            return jsonify({"error": "User ID not found in session"}), 400

        db_conn = get_db()  # Get database connection
        cursor = db_conn.execute(
            "SELECT id, totalCash, eventName, stockSold, stockBought, date FROM eventLog WHERE id = ?",
            (id,)  # Ensure this is a tuple by adding a comma
        )

        current_bal = db_conn.execute(
            "SELECT totalCash FROM user WHERE id = ?",
            (id,)
        ).fetchone()

        log_entries = [
            {
                'id': row['id'],
                'totalCash': row['totalCash'],
                'eventName': row['eventName'],
                'stockSold': row['stockSold'],
                'stockBought': row['stockBought'],
                'date': row['date']
            }
            for row in cursor.fetchall()
        ]

        return jsonify(log_entries), 200
    except Exception as e:
        print(f"Error fetching log entries: {e}")
        return jsonify({"error": "Failed to fetch log entries"}), 500
