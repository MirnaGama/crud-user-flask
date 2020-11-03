from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

# for password hash
import uuid 
from werkzeug.security import generate_password_hash

app = Flask(__name__)

###### DATABASE CONFIG
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///api.db' # SQLITE
db = SQLAlchemy(app)

###### MODEL TABLE FOR USER
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

###### ENDPOINTS 

# CREATE USER
@app.route('/user', methods=['POST'])
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


# SELECT ALL USERS
@app.route('/users', methods=['GET'])
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
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first() # find by public id

    if not user:
        return jsonify({'message': 'User not found!'})

    db.session.delete(user) # delete the user
    db.session.commit()

    return jsonify({'message' : 'The user has been successfully deleted!'})


if __name__ == '__main__':
    app.run(debug=True)