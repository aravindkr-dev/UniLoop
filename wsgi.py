from app import app, socketio
application = socketio.WSGIApp(app)
