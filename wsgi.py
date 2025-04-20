# wsgi.py
from app import app, socketio

# This exposes the socketio app to gunicorn
# No __main__, no run()
