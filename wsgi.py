from app import app, socketio

# Wrap the Flask app using the socketio WSGI app
application = socketio.get_wsgi_app(app)