from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy

# for password hash
import uuid 
from werkzeug.security import generate_password_hash, check_password_hash

# for jwt token
from flask_jwt import jwt
import datetime
from functools import wraps

app = Flask(__name__)

###### DATABASE CONFIG
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///api.db' # SQLITE
app.config['SECRET_KEY'] = 'secret' # for password's hash
db = SQLAlchemy(app)

###### MODEL TABLE FOR USER
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

# METHOD FOR CHECK THE TOKEN
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

###### ENDPOINTS 

# CREATE USER
@app.route('/user', methods=['POST'])
@token_required
def insert_into_user():

    # get info by request
    data = request.get_json()

    # creating hash for the password
    hashed_password = generate_password_hash(data['password'], method='sha256')

    # creating user
    user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    
    # commit into database
    db.session.add(user)
    db.session.commit()

    # return a message
    return jsonify({'message': 'New user has been successfully created!'})

@app.route('/')
def index():
    return "Welcome to my flask api!"

# SELECT ALL USERS
@app.route('/users', methods=['GET'])
@token_required
def get_all_users():
    outputUsers = [] # return var
    usersResponse = User.query.all() # select all users (query)

    # this will be needed so their real id won't be displayed
    for user in usersResponse:
        user_data = {} # creating a dic
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        outputUsers.append(user_data)

    return jsonify({'users': outputUsers}) # returning the users -- json format

# SELECT USER BY ID 
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_user_by_id(public_id):
    
    user = User.query.filter_by(public_id=public_id).first() # find by public id

    if not user:
        return jsonify({'message': 'User not found!'}) 
    
    # again, the real id shouldn't be displayed 
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

# DELETE USER BY ID
@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
#@token_required
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first() # find by public id

    if not user:
        return jsonify({'message': 'User not found!'})

    db.session.delete(user) # delete the user
    db.session.commit()

    return jsonify({'message' : 'The user has been successfully deleted!'})

# ENDPOINT FOR LOGIN
@app.route('/login', methods=['GET'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    # find user
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    # check password's hash
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : str(datetime.datetime.utcnow()+ datetime.timedelta(minutes=30))}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')}) # returns user's jwt token

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

if __name__ == '__main__':
    app.run(debug=True)