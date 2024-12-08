from unittest import TestCase
from unittest.mock import patch, MagicMock, call
from app.controllers.user_controller import create_user
from flask import jsonify
from app.__init__ import create_app


class TestCreateUser(TestCase):
    """Test suite for create_user functionality."""

    def setUp(self):
        """Sets up test environment and database for testing."""
        self.app = create_app()
        # Activate testing mode for test_database.db
        self.app.config['TESTING'] = True
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

    def tearDown(self):
        """Tear down the app context after testing."""
        self.app_context.pop()

    # 1. Test for Successful User Creation
    @patch("app.controllers.user_controller.get_db")
    @patch("app.controllers.user_controller.generate_password_hash")
    def test_create_user_success(self, mock_generate_password_hash, mock_get_db):
        """
        Test case for successfully creating a new user.
        Verifies that a user is added to the database when the input is valid.
        """
        mock_db_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_db.return_value = mock_db_conn

        # Mock query
        mock_db_conn.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None  # No existing user

        # Mock password hashing
        mock_generate_password_hash.return_value = "hashedpassword"

        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "securepassword*123"}
        )

        mock_db_conn.execute.assert_any_call(
            "SELECT * FROM user WHERE username = ?", ("testuser",)
        )
        mock_db_conn.execute.assert_any_call(
            "INSERT INTO user (username, password, totalCash) VALUES (?, ?, ?)",
            ("testuser", "hashedpassword", 100000),
        )
        mock_db_conn.commit.assert_called_once()

        # Assertions for HTTP response
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json, {"message": "User created successfully"})

    # 2. Test for Missing Username
    def test_create_user_missing_username(self):
        """
        Test case for missing username.
        Verifies that the API returns a 400 error when username is not provided.
        """

        response = self.client.post(
            '/api/user/create_user',
            json={"password": "securepassword*123"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Username and password are required"}
        )

    # 3. Test for Missing Password
    def test_create_user_missing_password(self):
        """
        Test case for missing password.
        Verifies that the API returns a 400 error when password is not provided.
        """

        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Username and password are required"}
        )

    # 4. Test User Already Exists
    @patch("app.controllers.user_controller.get_db")
    def test_create_user_existing_user(self, mock_get_db):
        """
        Test case for creating a user with an already existing username.
        Verifies that the API returns a 409 error when the username is taken.
        """

        mock_db_conn = MagicMock()
        mock_get_db.return_value = mock_db_conn
        mock_db_conn.execute.return_value.fetchone.return_value = {
            "username": "testuser"  # Mock existing user
        }

        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "securepassword*123"}
        )

        mock_db_conn.execute.assert_called_once_with(
            "SELECT * FROM user WHERE username = ?", ("testuser",)
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json, {"error": "Username already taken"})

    # 5. Boundary Value Analysis for Username
    @patch("app.controllers.user_controller.get_db")
    def test_username_boundary_values(self, mock_get_db):
        """
        Test case for username boundary values.
        Verifies correct behavior for usernames of valid and invalid lengths.
        """

        mock_db_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_db.return_value = mock_db_conn
        mock_db_conn.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None  # No existing user

        # 5.1 Username too short (2 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "ab", "password": "Password@123"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Username should be 1-15 characters in length"})

        # 5.2 Minimum valid length for username (3 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "aaa", "password": "Password@123"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json, {"message": "User created successfully"})

        # 5.3 Maximum valid length for username (15 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "a" * 15, "password": "Password@123"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json, {"message": "User created successfully"})

        # 5.4 Username too long (16 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "a" * 16, "password": "Password@123"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Username should be 1-15 characters in length"})

    # 6. Boundary Value Analysis for Password
    @patch("app.controllers.user_controller.get_db")
    def test_password_boundary_values(self, mock_get_db):
        """
        Test case for password boundary values.
        Verifies correct behavior for passwords of valid and invalid lengths.
        """

        mock_db_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_db.return_value = mock_db_conn
        mock_db_conn.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None  # No existing user

        # 6.1 Password too short (7 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "Pass@1"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Password should be 8-20 characters in length"})

        # 6.2 Minimum valid length for password (8 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser1", "password": "Pass@123"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json, {"message": "User created successfully"})

        # 6.3 Maximum valid length for password (20 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser2", "password": "P@ssword123456789010"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json, {"message": "User created successfully"})

        # 6.4 Password too long (21 characters)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "P@ssword1234567890101"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Password should be 8-20 characters in length"})

    # 7. Equivalence Partitioning for Password
    @patch("app.controllers.user_controller.get_db")
    def test_password_equivalence_partitioning(self, mock_get_db):
        """
        Test case for equivalence partitioning of passwords.
        Verifies correct behavior for passwords missing specific requirements.
        """

        mock_db_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_get_db.return_value = mock_db_conn
        mock_db_conn.execute.return_value = mock_cursor
        mock_cursor.fetchone.return_value = None  # No existing user

        # 7.1 Missing special character
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "Password123"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Password must contain at least one special character"})

        # 7.2 Missing number
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "Password@"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json, {"error": "Password must contain at least one number"})

        # 7.3 Missing special character and number
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "Password"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json, {
                         "error": "Password must contain at least one number"})

        # 7.4 Valid password (including special character and number)
        response = self.client.post(
            '/api/user/create_user',
            json={"username": "testuser", "password": "Password@123"}
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json, {"message": "User created successfully"})
