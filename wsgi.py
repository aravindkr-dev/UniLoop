from app import app, socketio

# Expose the SocketIO instance directly to Gunicorn
application = socketio
