# app/__init__.py

from flask import Flask
from config import Config
from flask_wtf.csrf import CSRFProtect

def create_app(config_class=Config):
    app = Flask(__name__)
    
    # Carrega as configurações a partir do objeto Config
    app.config.from_object(config_class)

    # Inicializar proteção CSRF
    csrf = CSRFProtect(app)

    # Registra as rotas (views) na aplicação
    # É importante importar aqui para evitar importações circulares
    from app import routes
    app.register_blueprint(routes.bp)

    return app