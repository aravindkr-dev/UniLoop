from app import app, socketio

# This is the correct callable for Gunicorn
application = socketio.run(app, host='0.0.0.0', port=4000)
