# config.py

import os

class Config:
    """Configurações da aplicação Flask."""
    # Chave secreta para proteger sessões e cookies.
    # Em produção, use uma variável de ambiente.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'uma-chave-secreta-muito-dificil-de-adivinhar'

