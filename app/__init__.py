# app/__init__.py

from flask import Flask
from config import Config

def create_app(config_class=Config):
    """
    Cria e configura uma instância da aplicação Flask.
    Este é o padrão "Application Factory".
    """
    app = Flask(__name__)
    
    # Carrega as configurações a partir do objeto Config
    app.config.from_object(config_class)

    # Registra as rotas (views) na aplicação
    # É importante importar aqui para evitar importações circulares
    from app import routes
    app.register_blueprint(routes.bp)

    return app