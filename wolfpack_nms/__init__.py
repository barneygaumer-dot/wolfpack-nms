from flask import Flask
from .db import init_db,close_db

def create_app():
    app=Flask(__name__)
    app.secret_key="wolfpack-nms"

    from .web import bp
    app.register_blueprint(bp)

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    return app
