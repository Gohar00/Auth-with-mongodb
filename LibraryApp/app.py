from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from bson import ObjectId
from functools import wraps
from flask import g
import json
import pymongo
import bcrypt
import jwt
import jsonschema
import os
import base64
# from convedrt import base64_encoded


blacklisted_tokens = set()
SECRET_KEY = os.urandom(24).hex()
app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/myappdb'
mongo = pymongo.MongoClient(app.config['MONGO_URI'])
app.config['SECRET_KEY'] = SECRET_KEY


with open('user_schema.json', 'r') as schema_file:
    user_schema = json.loads(schema_file.read())

with open('book_schema.json', 'r') as schema_file:
    book_schema = json.loads(schema_file.read())

ROLES = ['new', 'standard', 'banned', 'admin']


# Function to validate the incoming JSON data against the user schema
def validate_user_schema(data):
    try:
        jsonschema.validate(instance=data, schema=user_schema)
    except jsonschema.exceptions.ValidationError as e:
        return str(e)
    return None


# Function to validate book data
def validate_book_schema(data):
    try:
        jsonschema.validate(instance=data, schema=book_schema)
    except jsonschema.exceptions.ValidationError as e:
        return str(e)
    return None


# Function to hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


# Function to check if a password matches the hashed password
def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


# Modify token_required decorator to check for blacklisted tokens
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        access_token = request.headers.get('Authorization')

        if not access_token:
            return jsonify({'message': 'Token is missing'}), 401

        if access_token in blacklisted_tokens:
            return jsonify({'message': 'Token has been revoked'}), 401

        try:
            data = jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
            user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401

        # Pass the user's ID and role to the route function
        g.user_id = user_id
        g.user_role = user_role

        return f(*args, **kwargs)

    return decorated


# Register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate the incoming JSON data against the user schema
    validation_error = validate_user_schema(data)

    if validation_error:
        return jsonify({'message': 'Invalid data: ' + validation_error}), 400

    full_name = data['full_name']
    email = data['email']
    password = data['password']
    role = data['role']

    # Check if the user already exists
    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        return jsonify({'message': 'This email is already used'}), 409

    # Hash the password before saving it
    hashed_password = hash_password(password)

    new_user = {
        'full_name': full_name,
        'email': email,
        'password': hashed_password,
        'role': role
    }

    mongo.db.users.insert_one(new_user)

    return jsonify({'message': 'Successfully added'}), 201


# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = mongo.db.users.find_one({'email': email})

    if not user:
        return jsonify({'message': 'User not found'}), 401

    # Check if the provided password matches the stored hashed password
    if check_password(user['password'], password):
        # Issue a JWT with user information (user_id and role)
        access_token = jwt.encode({'user_id': str(user['_id']), 'role': user['role'], 'exp': datetime.utcnow() + timedelta(minutes=10)}, app.config['SECRET_KEY'])

        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


# Implement the /logout route
@app.route('/logout', methods=['POST'])
@token_required  # Keep this decorator
def logout():

    # Add the current token to the blacklist
    access_token = request.headers.get('Authorization')
    blacklisted_tokens.add(access_token)

    return jsonify({'message': 'Logged out successfully'}), 200


# Change the role of a user by an Admin
@app.route('/change_role/<user_id>', methods=['PUT'])
@token_required
def change_role(user_id):
    user_role = g.user_role

    current_user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

    if not current_user:
        return jsonify({'message': 'User not found'}), 404

    if user_role != 'admin':
        return jsonify({'message': 'Permission denied'}), 403

    data = request.get_json()
    new_role = data['new_role']

    if new_role not in ROLES:
        return jsonify({'message': 'Invalid role'}), 400

    if current_user['role'] == 'new' and new_role not in ['standard', 'banned']:
        return jsonify({'message': 'Invalid role change'}), 400

    # Update the user's role
    mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})

    # Return the updated user with the new role
    updated_user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})

    return jsonify({'message': 'Role changed successfully', 'user': updated_user}), 200


# Get data of all users (no user-specific role required)
@app.route('/users', methods=['GET'])
@token_required
def get_users():
    user_role = g.user_role

    if user_role != 'admin':
        return jsonify({'message': 'Permission denied'}), 403

    # Filter users based on their role
    query_filter = {}  # An empty filter will retrieve all users
    users = list(mongo.db.users.find(query_filter, {'password': 0}))

    # Convert ObjectId to strings
    for user in users:
        user['_id'] = str(user['_id'])

    return jsonify({'users': users})


@app.route("/books/update/<string:id>", methods=["PUT"])
@token_required
def update_book(id):
    user_role = g.user_role

    if user_role != 'admin':
        return jsonify({"message": "Permission denied"}), 403

    data = request.get_json()

    validation_error = validate_book_schema(data)

    if validation_error:
        return jsonify({'message': 'Invalid data: ' + validation_error}), 400

    # Find the book by its unique ID
    existing_book = mongo.myappdb.books.find_one({'_id': ObjectId(id)})

    if not existing_book:
        return jsonify({'message': 'Book not found'}), 404

    # Update the book's fields with the new data
    mongo.myappdb.books.update_one({'_id': ObjectId(id)}, {'$set': data})

    return jsonify({'message': 'Book updated successfully'}), 200


@app.route("/books/delete/<string:id>", methods=["DELETE"])
@token_required
def delete_book(id):
    user_role = g.user_role

    if user_role != 'admin':
        return jsonify({"message": "Permission denied"}), 403

    # Find the book by its unique ID
    existing_book = mongo.myappdb.books.find_one({'_id': ObjectId(id)})

    if not existing_book:
        return jsonify({'message': 'Book not found'}), 404

    # Delete the book by its unique ID
    mongo.myappdb.books.delete_one({'_id': ObjectId(id)})

    return jsonify({'message': 'Book deleted successfully'}), 200


@app.route('/view_books', methods=["GET"])
@token_required
def view_books():
    # Get query parameters from the URL
    author = request.args.get('author')
    subject = request.args.get('subject')

    # Define the query filter based on the provided parameters
    query_filter = {}

    if author:
        query_filter['author_name'] = author

    if subject:
        query_filter['tag'] = subject

    # Retrieve books from the database based on the filter
    books = list(mongo.myappdb.books.find(query_filter))

    # Convert bytes objects to strings
    for book in books:
        if 'some_field' in book:
            book['some_field'] = book['some_field'].decode('utf-8')

    # Convert books to JSON string using a custom encoder
    json_books = json.dumps({'books': books}, default=str)

    return json_books, 200, {'Content-Type': 'application/json'}


@app.route('/view_books/<string:book_id>', methods=["GET"])
@token_required
def view_book(book_id):
    book = mongo.myappdb.books.find_one({"_id": ObjectId(book_id)})
    if not book:
        return jsonify({"message": "Book not found"}), 404

    book['_id'] = str(book['_id'])

    # Convert the binary data to a Base64 encoded string
    book['file']['data'] = base64.b64encode(book['file']['data']).decode('utf-8')

    return jsonify({'book': book})

#TODO
# @app.route('/upload', methods=['POST'])
# @token_required
# def upload_book():
#     # Check if a file was included in the request
#     if 'file' not in request.files:
#         return jsonify({"message": "No file part"}), 400
#
#     file = request.files['file']
#
#     if file.filename == '':
#         return jsonify({"message": "No selected file"}), 400
#
#     data = request.form.to_dict()
#     file_data = {
#         "filename": file.filename,
#         "originalName": file.filename,
#         "contentType": file.content_type,
#         "data": base64.b64encode(file.read()).decode('utf-8')
#     }
#     data['file'] = json.dumps(file_data)
#
#     validation_error = validate_book_schema(data)
#
#     if validation_error:
#         return jsonify({'message': 'Invalid data: ' + validation_error}), 400
#
#     mongo.myappdb.books.insert_one(data)
#
#     return jsonify({'message': 'File uploaded and book record created successfully'}), 201


if __name__ == "__main__":
    app.run(debug=True)
