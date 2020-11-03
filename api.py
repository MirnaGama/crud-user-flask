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

if __name__ == '__main__':
    app.run(debug=True)