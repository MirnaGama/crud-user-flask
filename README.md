# About the project:
RESTFul API in Flask with User CRUD using Flask-SQLAlchemy

### You should install:
* Flask
* Flask SQL Alchemy

### Creating database:
```bash
.../api-jwt> python
>>> from api import db
>>> db.create_all()
>>> exit()
```

### Checking the tables:
```bash
.../api-jwt> sqlite3 api.db
sqlite> .tables
```

### Starting the api:
```bash
.../crud-user-flask> python api.py
```