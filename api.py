from flask import Flask
from flask_sqlalchemy import SQLAlchemy

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

###### ENDPOINTS BELOW

if __name__ == '__main__':
    app.run(debug=True)