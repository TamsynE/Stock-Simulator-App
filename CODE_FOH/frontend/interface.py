from flask import Flask, request, jsonify
import requests
from app import create_app  # Import the create_app function
import os
app = create_app()  # Initialize the Flask application

# Define the backend URL
BACKEND_URL = os.getenv('BACKEND_URL')

# @app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
# def proxy(path):
#     # Forward the request to the backend
#     url = f"{BACKEND_URL}/api/{path}"
#     try:
#         response = requests.request(
#             method=request.method,
#             url=url,
#             headers={key: value for key, value in request.headers if key != 'Host'},
#             json=request.get_json(silent=True),
#             params=request.args
#         )
        
#         # Return the response from the backend
#         return jsonify(response.json()), response.status_code
#     except requests.exceptions.RequestException as e:
#         return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001)  # Start the Flask app on port 5001