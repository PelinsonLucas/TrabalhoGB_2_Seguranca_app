# run.py

from app import create_app

# Cria a aplicação usando a função factory
app = create_app()

if __name__ == '__main__':
    # debug=True é útil para desenvolvimento, mas deve ser desativado em produção.
    app.run(host='0.0.0.0', port=5000, debug=True)
