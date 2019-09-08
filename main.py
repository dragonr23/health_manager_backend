from app import app, db
from app.models import User, Record
import os

@app.shell_context_processor
def make_shell_context():
    return { 'db': db, 'User': User, 'Record': Record}


if __name__ == '__main__':
    app.debug = True
    port = int(os.environ.get('PORT', 80))
    app.run(host='0.0.0.0', port=port)
