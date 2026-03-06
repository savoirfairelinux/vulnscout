from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

#: Shared SQLAlchemy instance.  Bind it to the app with ``db.init_app(app)``.
db = SQLAlchemy()

migrate = Migrate()
