# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
import uuid
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///collab.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

socketio = SocketIO(app)
db = SQLAlchemy(app)

active_users = {}

class SavedRoom(db.Model):
    id = db.Column(db.String(6), primary_key=True)
    content = db.Column(db.Text)

@app.route('/')
def index():
    return redirect(url_for('create_room'))

@app.route('/room')
def create_room():
    room_id = uuid.uuid4().hex[:6]
    return redirect(url_for('room', room_id=room_id))

@app.route('/room/<room_id>')
def room(room_id):
    saved = SavedRoom.query.get(room_id)
    content = saved.content if saved else ""
    return render_template('room.html', room_id=room_id, content=content)

@app.route('/save/<room_id>', methods=['POST'])
def save_code(room_id):
    data = request.get_json()
    code = data.get('code', '')
    snippet = SavedRoom.query.get(room_id)
    if snippet:
        snippet.content = code
    else:
        snippet = SavedRoom(id=room_id, content=code)
        db.session.add(snippet)
    db.session.commit()
    return jsonify({"status": "saved"})

@socketio.on('join')
def handle_join(data):
    room = data['room']
    sid = request.sid
    join_room(room)
    active_users.setdefault(room, set()).add(sid)
    emit('active_users', list(active_users[room]), to=room)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    for room, users in active_users.items():
        if sid in users:
            users.remove(sid)
            emit('active_users', list(users), to=room)
            break

@socketio.on('code_change')
def handle_code_change(data):
    room = data['room']
    code = data['code']
    emit('code_update', code, to=room, include_self=False)

if __name__ == '__main__':
    os.makedirs("templates", exist_ok=True)
    with open("templates/room.html", "w") as f:
        f.write("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Live Room {{ room_id }}</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.4.12/ace.js"></script>
  <script src="https://cdn.socket.io/4.6.1/socket.io.min.js"></script>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    #editor { height: 500px; width: 100%; }
  </style>
</head>
<body class="p-4">
  <h1>Collaborative Room: {{ room_id }}</h1>
  <div id="editor">{{ content }}</div>
  <div class="mt-3">
    <button id="saveBtn" class="btn btn-success">Save Code</button>
    <span class="ms-3 text-muted" id="userCount"></span>
  </div>

  <script>
    const socket = io();
    const roomId = '{{ room_id }}';
    socket.emit('join', { room: roomId });

    const editor = ace.edit("editor");
    editor.setTheme("ace/theme/monokai");
    editor.session.setMode("ace/mode/python");

    let ignoreChange = false;
    editor.on("change", function() {
      if (ignoreChange) return;
      const code = editor.getValue();
      socket.emit("code_change", { room: roomId, code: code });
    });

    socket.on("code_update", function(code) {
      ignoreChange = true;
      editor.setValue(code, -1);
      ignoreChange = false;
    });

    document.getElementById("saveBtn").onclick = () => {
      const code = editor.getValue();
      fetch(`/save/${roomId}`, {
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      })
        .then(res => res.json())
        .then(data => alert("Code saved!"));
    };

    socket.on("active_users", function(users) {
      document.getElementById("userCount").innerText = `Users online: ${users.length}`;
    });
  </script>
</body>
</html>
""")
    socketio.run(app, debug=True)
