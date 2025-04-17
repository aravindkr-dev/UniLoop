from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///collegehub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Association table
project_participants = db.Table('project_participants',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'))
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(255))
    bio = db.Column(db.String(500))

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref='created_projects', foreign_keys=[created_by])
    members = db.relationship('User', secondary=project_participants, backref='projects')



class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(10), default='pending')  # 'pending', 'accepted', 'rejected'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])


class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])



# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        current_user.email = request.form['email']
        current_user.bio = request.form['bio']
        current_user.profile_picture = request.form['profile_picture']
        db.session.commit() #No need of adding because we are updating th exsisting data
        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))

    user_projects = current_user.projects
    print(current_user.profile_picture)
    return render_template('profile.html', user=current_user, user_projects=user_projects)

@app.route('/projects/create', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        project = Project(
            name=name,
            description=description,
            created_by=current_user.id
        )
        project.members.append(current_user)
        db.session.add(project)
        db.session.commit()
        flash('Project created!', 'success')
        return redirect(url_for('project_detail', project_id=project.id))
    return render_template('create_project.html')


@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template('project_detail.html', project=project)  # <- THIS LINE

@app.route('/projects/<int:project_id>/join')
@login_required
def join_project(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user not in project.members:
        project.members.append(current_user)
        db.session.commit()
        flash('You joined the project!', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/projects/<int:project_id>/leave')
@login_required
def leave_project(project_id):
    project = Project.query.get_or_404(project_id)
    if current_user in project.members:
        project.members.remove(current_user)
        db.session.commit()
        flash('You left the project.', 'warning')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/friends')
@login_required
def friends():
    # Fetch friendships where current_user is either user1 or user2
    friendships = Friendship.query.filter(
        (Friendship.user1_id == current_user.id) | (Friendship.user2_id == current_user.id)
    ).all()

    friends_list = []

    for friendship in friendships:
        if friendship.user1_id == current_user.id:
            friends_list.append(friendship.user2)
        else:
            friends_list.append(friendship.user1)

    # Debugging: Print the friends' names
    for friend1 in friends_list:
        print(friend1.first_name)  # This should print the names of the friends

    return render_template('list_friends.html', friends=friends_list)



@app.route('/friend/search', methods=['GET', 'POST'])
@login_required
def search_friends():
    users = []
    query = ''
    if request.method == 'POST':
        query = request.form['query']
        users = User.query.filter(
            (User.first_name.ilike(f'%{query}%')) |
            (User.last_name.ilike(f'%{query}%')) |
            (User.email.ilike(f'%{query}%'))
        ).filter(User.id != current_user.id).all()

    # Fetch existing friends
    friend_ids = {f.user2_id for f in Friendship.query.filter_by(user1_id=current_user.id)}
    friend_ids |= {f.user1_id for f in Friendship.query.filter_by(user2_id=current_user.id)}

    # Pending requests
    pending_ids = {req.to_user_id for req in FriendRequest.query.filter_by(from_user_id=current_user.id, status='pending')}

    # Incoming requests
    friend_requests = FriendRequest.query.filter_by(to_user_id=current_user.id, status='pending').all()

    return render_template(
        'search_friends.html',
        users=users,
        friends=friend_ids,
        pending_requests=pending_ids,
        friend_requests=friend_requests
    )

@app.route('/friend/request/<int:user_id>')
@login_required
def send_friend_request(user_id):
    # Prevent duplicates
    existing = FriendRequest.query.filter_by(from_user_id=current_user.id, to_user_id=user_id).first()
    already_friends = Friendship.query.filter(
        ((Friendship.user1_id == current_user.id) & (Friendship.user2_id == user_id)) |
        ((Friendship.user2_id == current_user.id) & (Friendship.user1_id == user_id))
    ).first()
    if not existing and not already_friends:
        req = FriendRequest(from_user_id=current_user.id, to_user_id=user_id)
        db.session.add(req)
        db.session.commit()
        flash('Friend request sent!', 'success')
    else:
        flash('Friend request already sent or already friends.', 'warning')
    return redirect(url_for('search_friends'))

@app.route('/friend/accept/<int:request_id>')
@login_required
def accept_friend_request(request_id):
    req = FriendRequest.query.get_or_404(request_id)
    if req.to_user_id == current_user.id and req.status == 'pending':
        req.status = 'accepted'
        friendship = Friendship(user1_id=req.from_user_id, user2_id=req.to_user_id)
        db.session.add(friendship)
        db.session.commit()
        flash('Friend request accepted.', 'success')
    return redirect(url_for('search_friends'))

@app.route('/friend/reject/<int:request_id>')
@login_required
def reject_friend_request(request_id):
    req = FriendRequest.query.get_or_404(request_id)
    if req.to_user_id == current_user.id and req.status == 'pending':
        req.status = 'rejected'
        db.session.commit()
        flash('Friend request rejected.', 'danger')
    return redirect(url_for('search_friends'))


# Run
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
