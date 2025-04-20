import uuid
from flask import Flask, abort, jsonify, render_template, redirect, url_for, request, flash
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import insert
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from flask_migrate import Migrate
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, login_required
from datetime import datetime
import uuid
from flask_wtf.csrf import CSRFProtect
import humanize
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///collegehub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)  
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
# Update this line in your app configuration
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'




# Make sure you have CORS properly set up if needed
socketio = SocketIO(app)  # For development, restrict in production

# Dictionary to track active users in each room
active_users = {}




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
    
    # Additional profile fields
    college = db.Column(db.String(200))
    #skills = db.Column(db.String(500))
    github = db.Column(db.String(255))
    linkedin = db.Column(db.String(255))
    
    # Privacy and notification settings could be added here or in separate models
    profile_visibility = db.Column(db.String(20), default='public')
    friend_request_setting = db.Column(db.String(20), default='everyone')
    
    # Relationships
    owned_projects = db.relationship('Project', back_populates='owner')
    #joined_projects = db.relationship('Project', secondary='project_members', back_populates='team_members')
    joined_projects = db.relationship('Project', 
                                     secondary='project_members',
                                     primaryjoin="User.id == ProjectMember.user_id",
                                     secondaryjoin="ProjectMember.project_id == Project.id",
                                     viewonly=True)

    skills = db.Column(db.Text)
    
    # Helper method to get skills as a list
    def get_skills_list(self):
        if not self.skills:
            return []
        return [skill.strip().lower() for skill in self.skills.split(',')]

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    github_url = db.Column(db.String(255))
    demo_url = db.Column(db.String(255))
    documentation_url = db.Column(db.String(255))  # Added for documentation link
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visibility = db.Column(db.String(20), default='public')
    likes = db.Column(db.Integer, default=0)

    # Relationships
    owner = db.relationship('User', foreign_keys=[owner_id], back_populates='owned_projects')
    team_members = db.relationship('ProjectMember', back_populates='project', cascade="all, delete-orphan")
    tags = db.relationship('Tag', secondary='project_tags', back_populates='projects')
    activities = db.relationship('ProjectActivity', back_populates='project', cascade="all, delete-orphan", 
                                order_by="desc(ProjectActivity.timestamp)")
    code_rooms = db.relationship('CodeRoom', back_populates='project', cascade="all, delete-orphan")

    @property
    def members(self):
        return [member.user for member in self.team_members]
    
    # Helper method to check if a user is a member
    def has_member(self, user):
        for member in self.team_members:
            if member.user_id == user.id:
                return True
        return False
        
    # Helper property to get formatted team members with proper roles
    @property
    def formatted_team_members(self):
        """Returns team members with additional owner flag for template use"""
        members = []
        # Add owner first
        owner_data = {
            'user_id': self.owner_id,
            'first_name': self.owner.first_name,
            'last_name': self.owner.last_name,
            'profile_pic': self.owner.profile_pic if hasattr(self.owner, 'profile_pic') else None,
            'is_owner': True,
            'role': 'Owner'
        }
        members.append(owner_data)
        
        # Add other members
        for member in self.team_members:
            if member.user_id != self.owner_id:  # Skip owner as we already added them
                members.append({
                    'user_id': member.user_id,
                    'first_name': member.user.first_name,
                    'last_name': member.user.last_name,
                    'profile_pic': member.user.profile_pic if hasattr(member.user, 'profile_pic') else None,
                    'is_owner': False,
                    'role': member.role
                })
        return members

# Define ProjectMember model for many-to-many relationship with additional data
class ProjectMember(db.Model):
    __tablename__ = 'project_members'
    
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    role = db.Column(db.String(50))
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    project = db.relationship('Project', back_populates='team_members')
    user = db.relationship('User')

# Create Tag model
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    
    # Relationships
    projects = db.relationship('Project', secondary='project_tags', back_populates='tags')

# Create project_tags association table
project_tags = db.Table('project_tags',
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

# Create ProjectActivity model for tracking activities
class ProjectActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.String(255), nullable=False)
    icon = db.Column(db.String(50))  # For FontAwesome icons
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    project = db.relationship('Project', back_populates='activities')
    user = db.relationship('User')


"""team_members = db.relationship(
    'User',
    secondary=ProjectMember,
    backref='joined_projects'
)
"""

class Messages():
    id = db.Column(db.Integer , primary_key = True)
    from_user = db.Column(db.String(300) , nullable = False)
    to_user = db.Column(db.String(300) , nullable = False)
    msg = db.Column(db.String(5000) , nullable = False)
    view = db.Column(db.String(50))


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

class CodeRoom(db.Model):
    id = db.Column(db.String(6), primary_key=True)
    content = db.Column(db.Text)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    language = db.Column(db.String(50), default='python')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Remove this line or replace with project = db.relationship('Project')
    project = db.relationship('Project', back_populates='code_rooms')

# Update your login route to handle redirects properly
@app.template_filter('timeago')
def timeago_filter(dt):
    if not dt:
        return "unknown time"
    return humanize.naturaltime(datetime.utcnow() - dt)
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already authenticated, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            # Redirect to the page user was trying to access, or dashboard
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')

# User loader
@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, user_id)
    return user

# Routes
@app.route('/')
@login_required
def dashboard():
    # Get owned projects
    owned_projects = Project.query.filter_by(owner_id=current_user.id).all()
    
    # Get projects where user is a team member
    joined_projects = current_user.joined_projects
    
    # Get friendships
    friendships = Friendship.query.filter(
        (Friendship.user1_id == current_user.id) | (Friendship.user2_id == current_user.id)
    ).all()
    
    # Create friends list
    friends_list = []
    for friendship in friendships:
        if friendship.user1_id == current_user.id:
            friends_list.append(friendship.user2)
        else:
            friends_list.append(friendship.user1)
    
    # Get pending friend requests
    friend_requests = FriendRequest.query.filter_by(to_user_id=current_user.id, status='pending').all()
    
    return render_template(
        'dashboard.html',
        owned_projects=owned_projects,
        joined_projects=joined_projects,
        friendships=friendships,
        friends_list=friends_list,
        friend_requests=friend_requests
    )

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


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.bio = request.form.get('bio')
        current_user.college = request.form.get('college')
        current_user.skills = request.form.get('skills')
        current_user.github = request.form.get('github')
        current_user.linkedin = request.form.get('linkedin')

        # Handle profile picture upload
        if 'profile_picture' in request.files:
            pic = request.files['profile_picture']
            if pic and pic.filename != '':
                filename = secure_filename(pic.filename)
                filepath = os.path.join('static/uploads', filename)
                pic.save(filepath)
                current_user.profile_picture = filename

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('settings.html')


@app.route('/profile', methods=['GET', 'POST'])
@app.route('/profile/<int:user_id>', methods=['GET'])
@login_required
def profile(user_id=None):
    # If no user_id is specified, show the current user's profile
    if user_id is None:
        user = current_user
    else:
        user = User.query.get_or_404(user_id)
    
    # Handle POST requests (profile updates) - only for current user
    if request.method == 'POST' and user.id == current_user.id:
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.bio = request.form['bio']
        user.skills = request.form['skills']
        user.college = request.form['college']

        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join('static/uploads', filename)
                file.save(filepath)
                user.profile_picture = filename
        
        db.session.commit()
        flash("Profile updated!", "success")
        return redirect(url_for('profile'))
    
    # Get user's projects (both owned and participated)
    user_projects = user.owned_projects + user.joined_projects
    
    # Get user's friends
    friendships = Friendship.query.filter(
        (Friendship.user1_id == user.id) | (Friendship.user2_id == user.id)
    ).all()

    friends_list = []
    for friendship in friendships:
        if friendship.user1_id == user.id:
            friends_list.append(friendship.user2)
        else:
            friends_list.append(friendship.user1)
    
    return render_template(
        'profile/profile.html', 
        user=user, 
        user_projects=user_projects,
        friends_list=friends_list,
        is_own_profile=(user.id == current_user.id)
    )
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


@app.route('/my-projects', methods=['GET', 'POST'])
@login_required
def my_projects():
    friendships = Friendship.query.filter(
        (Friendship.user1_id == current_user.id) | (Friendship.user2_id == current_user.id)
    ).all()

    friends_list = []

    for friendship in friendships:
        if friendship.user1_id == current_user.id:
            friends_list.append(friendship.user2)
        else:
            friends_list.append(friendship.user1)
    
    # Modified query using user_id instead of id
    projects = Project.query.filter(
        (Project.owner_id == current_user.id) | 
        (Project.team_members.any(user_id=current_user.id))  # Changed id to user_id
    ).all()

    return render_template('project/dashboard.html', projects=projects)

@app.route('/create_project', methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        github_url = request.form['github_url']
        demo_url = request.form.get('demo_url', '')
        visibility = request.form['visibility']
        
        # Validate that at least one URL is provided
        if not github_url and not demo_url:
            flash("Please provide at least one project link (GitHub or Demo URL)", "danger")
            return render_template('project/create_project.html')

        project = Project(
            title=title,
            description=description,
            github_url=github_url,
            demo_url=demo_url,
            owner_id=current_user.id,
            visibility=visibility
        )
        db.session.add(project)
        db.session.commit()
        flash("Project created successfully!", "success")
        return redirect(url_for('my_projects'))
    elif request.method == 'GET':
        return render_template('project/create_project.html')


"""
@app.route('/project/add_member/<int:user_id>/<string:role>/<int:project_id>' , methods = ['POST'])
@login_required
def add_member(user_id , role , project_id):
    member_obj = project_members(project_id = project_id , user_id = user_id , role = role )
    db.session.add(member_obj)
    db.session.commit()
    return redirect('create_project')
"""
@app.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    friendships = Friendship.query.filter(
        (Friendship.user1_id == current_user.id) | (Friendship.user2_id == current_user.id)
    ).all()

    friends_list = []

    for friendship in friendships:
        if friendship.user1_id == current_user.id:
            friends_list.append(friendship.user2)
        else:
            friends_list.append(friendship.user1)

            
    project = Project.query.get_or_404(project_id)

    # Check if the current user is either the owner or a team member
    if project.owner_id != current_user.id and current_user not in project.team_members:
        flash("You do not have permission to view or edit this project.", "error")
        return redirect(url_for('my_projects'))  # Redirect to the user's projects if no permission

    # Handle POST request to update project details
    if request.method == 'POST':
        project.title = request.form['title']
        project.description = request.form['description']
        project.github_url = request.form['github_url']
        project.demo_url = request.form.get('demo_url', '')
        project.visibility = request.form['visibility']
        
        # Validate that at least one URL is provided
        if not project.github_url and not project.demo_url:
            flash("Please provide at least one project link (GitHub or Demo URL)", "danger")
            return render_template('project/edit_project.html', project=project, friends_list=friends_list)
            
        db.session.commit()
        flash("Project details updated successfully!", "success")
        return redirect(url_for('my_projects'))

    # If GET request, render the project page
    return render_template('project/edit_project.html', project=project, friends_list=friends_list)




@app.route('/project/add_member', methods=['POST'])
@login_required
def add_member():
    user_id = request.form.get('user_id')
    role = request.form.get('role')
    project_id = request.form.get('project_id')

    if not user_id or not role or not project_id:
        flash("Missing required fields.", "error")
        return redirect(url_for('edit_project', project_id=project_id))  # Go back to the edit page

    try:
        # Insert into the many-to-many relationship table
        db.session.execute(
            ProjectMember.insert().values(
                project_id=int(project_id),
                user_id=int(user_id),
                role=role,
                joined_at=datetime.utcnow()
            )
        )
        db.session.commit()
        flash("Member added successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error adding member: " + str(e), "error")

    return redirect(url_for('edit_project', project_id=project_id))




@app.route('/project/<int:project_id>', methods=['GET'])
@login_required
def project_page(project_id):
    project = Project.query.get_or_404(project_id)

    # Check if the user is the owner or a member of the project
    if project.owner_id != current_user.id and current_user not in project.team_members:
        flash("You do not have permission to view this project.", "error")
        return redirect(url_for('my_projects'))  # Redirect if not authorized

    return render_template('project/view_project.html', project=project)




@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)

    # Only the owner can delete the project
    if project.owner_id != current_user.id:
        flash("You are not authorized to delete this project.", "error")
        return redirect(url_for('my_projects'))

    try:
        db.session.delete(project)
        db.session.commit()
        flash("Project deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting project: {str(e)}", "error")

    return redirect(url_for('my_projects'))


@app.route('/project/<int:project_id>/code')
@login_required
def project_code_rooms(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    if project.owner_id != current_user.id and current_user not in project.team_members:
        flash('You do not have access to this project.', 'danger')
        return redirect(url_for('home'))
    
    code_rooms = CodeRoom.query.filter_by(project_id=project_id).all()
    return render_template('project/project_code_rooms.html', project=project, code_rooms=code_rooms)

@app.route('/project/<int:project_id>/code/create', methods=['GET', 'POST'])
@login_required
def create_code_room(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has access to this project
    if project.owner_id != current_user.id and current_user not in project.team_members:
        flash('You do not have access to this project.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        language = request.form.get('language', 'python')
        room_id = uuid.uuid4().hex[:6]
        
        code_room = CodeRoom(
            id=room_id,
            project_id=project_id,
            language=language
        )
        
        db.session.add(code_room)
        db.session.commit()
        
        return redirect(url_for('code_room', room_id=room_id))
    
    return render_template('project/create_code_room.html', project=project)

# Make sure this route correctly loads the code room with the saved content
@app.route('/code/<room_id>')
@login_required
def code_room(room_id):
    try:
        room = CodeRoom.query.get_or_404(room_id)
        project = Project.query.get(room.project_id)
        
        # Check if user has access to this project
        if project.owner_id != current_user.id and current_user not in project.team_members:
            flash('You do not have access to this code room.', 'danger')
            return redirect(url_for('home'))
        
        # Log page access for debugging
        app.logger.info(f"User {current_user.id} accessing code room {room_id}")
        app.logger.debug(f"Room content length: {len(room.content or '')}")
        
        return render_template('project/code_room.html', room=room, project=project)
    except Exception as e:
        app.logger.error(f"Error accessing code room {room_id}: {str(e)}")
        flash('An error occurred while loading the code room.', 'danger')
        return redirect(url_for('my_projects'))

@csrf.exempt
@app.route('/save/<room_id>', methods=['POST'])
@login_required
def save_code(room_id):
    try:
        room = CodeRoom.query.get_or_404(room_id)
        project = Project.query.get(room.project_id)
        
        # Check if user has access to this project
        if project.owner_id != current_user.id and current_user not in project.team_members:
            return jsonify({"error": "Access denied"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data received"}), 400
            
        code = data.get('code', '')
        
        # Update the room content
        room.content = code
        room.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log successful save
        app.logger.info(f"Code saved for room {room_id} by user {current_user.id}")
        
        return jsonify({"status": "saved"})
    except Exception as e:
        # Log the error
        app.logger.error(f"Error saving code for room {room_id}: {str(e)}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/code/<room_id>/language', methods=['POST'])
@login_required
def update_language(room_id):
    room = CodeRoom.query.get_or_404(room_id)
    project = Project.query.get(room.project_id)
    
    # Check if user has access to this project
    if project.owner_id != current_user.id and current_user not in project.team_members:
        return jsonify({"error": "Access denied"}), 403
    
    data = request.get_json()
    language = data.get('language')
    
    if language:
        room.language = language
        db.session.commit()
        return jsonify({"status": "updated"})
    
    return jsonify({"error": "Invalid language"}), 400

# Socket.IO event handlers
@socketio.on('join')
def handle_join(data):
    try:
        room = data['room']
        user_id = data['user_id']
        username = data['username']
        sid = request.sid
        
        join_room(room)
        app.logger.info(f"User {user_id} joined room {room}")
        
        # Store user information with their session ID
        if room not in active_users:
            active_users[room] = {}
        
        active_users[room][sid] = {
            'user_id': user_id,
            'username': username
        }
        
        user_list = [
            {'user_id': details['user_id'], 'username': details['username']}
            for details in active_users[room].values()
        ]
        
        emit('active_users', user_list, to=room)
    except Exception as e:
        app.logger.error(f"Error in handle_join: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    try:
        sid = request.sid
        room_to_leave = None
        
        for room, users in active_users.items():
            if sid in users:
                room_to_leave = room
                user_details = users[sid]
                del users[sid]
                
                app.logger.info(f"User {user_details['user_id']} disconnected from room {room}")
                
                user_list = [
                    {'user_id': details['user_id'], 'username': details['username']}
                    for details in users.values()
                ]
                
                emit('active_users', user_list, to=room)
                break
        
        if room_to_leave:
            leave_room(room_to_leave)
    except Exception as e:
        app.logger.error(f"Error in handle_disconnect: {str(e)}")

@socketio.on('code_change')
def handle_code_change(data):
    try:
        room = data['room']
        code = data['code']
        emit('code_update', code, to=room, include_self=False)
    except Exception as e:
        app.logger.error(f"Error in handle_code_change: {str(e)}")

@app.route('/code/<room_id>/delete', methods=['POST'])
@login_required
def delete_code_room(room_id):
    room = CodeRoom.query.get_or_404(room_id)
    project = Project.query.get(room.project_id)
    
    # Check if user has permission (only project owner can delete code rooms)
    if project.owner_id != current_user.id:
        flash('Only the project owner can delete code rooms.', 'danger')
        return redirect(url_for('code_room', room_id=room_id))
    
    # Get project_id before deleting the room
    project_id = room.project_id
    
    # Clean up active users in this room
    if room_id in active_users:
        del active_users[room_id]
    
    # Delete the room
    db.session.delete(room)
    db.session.commit()
    
    flash('Code room deleted successfully.', 'success')
    return redirect(url_for('project_code_rooms', project_id=project_id))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    # Handle form submissions
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        
        # Account Information Update
        if form_type == 'account_info':
            current_user.first_name = request.form.get('first_name')
            current_user.last_name = request.form.get('last_name')
            current_user.email = request.form.get('email')
            db.session.commit()
            flash('Account information updated successfully!', 'success')
            
        # Profile Picture Update
        elif form_type == 'profile_picture':
            # Check if user wants to remove picture
            if request.form.get('remove_picture'):
                # If there's an existing picture, you might want to delete the file
                if current_user.profile_picture:
                    try:
                        os.remove(os.path.join('static/uploads', current_user.profile_picture))
                    except:
                        pass  # File might not exist
                current_user.profile_picture = None
                db.session.commit()
                flash('Profile picture removed.', 'success')
            # Handle new picture upload
            elif 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    # Check file size (5MB max)
                    if len(file.read()) > 5 * 1024 * 1024:
                        flash('File too large. Maximum size is 5MB.', 'danger')
                        return redirect(url_for('settings') + '#profile')
                    
                    # Reset file pointer after reading for size check
                    file.seek(0)
                    
                    # Save the file
                    filename = secure_filename(f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{file.filename}")
                    filepath = os.path.join('static/uploads', filename)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    
                    file.save(filepath)
                    
                    # Update user's profile picture in the database
                    current_user.profile_picture = filename
                    db.session.commit()
                    flash('Profile picture updated successfully!', 'success')
            
        # Profile Information Update
        elif form_type == 'profile_info':
            current_user.bio = request.form.get('bio')
            current_user.college = request.form.get('college')
            current_user.skills = request.form.get('skills')
            current_user.github = request.form.get('github')
            current_user.linkedin = request.form.get('linkedin')
            db.session.commit()
            flash('Profile information updated successfully!', 'success')
            
        # Change Password
        elif form_type == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Check if current password is correct
            if not bcrypt.check_password_hash(current_user.password, current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('settings') + '#security')
            
            # Check if new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('settings') + '#security')
            
            # Check password length
            if len(new_password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return redirect(url_for('settings') + '#security')
            
            # Update password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            db.session.commit()
            flash('Password changed successfully!', 'success')
            
        # Notification Settings
        elif form_type == 'notification_settings':
            # Here you would save the notification preferences
            # This would typically be stored in a separate NotificationSettings model
            flash('Notification preferences saved!', 'success')
            
        # Privacy Settings
        elif form_type == 'privacy_settings':
            # Here you would save the privacy settings
            # This would typically be stored in a separate PrivacySettings model
            flash('Privacy settings saved!', 'success')
    
    return render_template('settings.html')

# 1. First, let's update the Messages model to properly extend db.Model

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Define relationships with User model
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

# 2. Now let's add the necessary routes for messaging

@app.route('/messages')
@login_required
def messages():
    """View all conversations"""
    # Get list of users the current user has exchanged messages with
    sent_to = db.session.query(User).join(Message, Message.recipient_id == User.id)\
        .filter(Message.sender_id == current_user.id).distinct()
    
    received_from = db.session.query(User).join(Message, Message.sender_id == User.id)\
        .filter(Message.recipient_id == current_user.id).distinct()
    
    # Combine and remove duplicates
    conversation_partners = sent_to.union(received_from).all()
    
    # Count unread messages from each user
    unread_counts = {}
    for partner in conversation_partners:
        unread_count = Message.query.filter_by(
            sender_id=partner.id, 
            recipient_id=current_user.id,
            is_read=False
        ).count()
        unread_counts[partner.id] = unread_count
    
    return render_template(
        'messages/conversations.html', 
        conversation_partners=conversation_partners,
        unread_counts=unread_counts
    )

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def conversation(user_id):
    """View and send messages in a conversation with a specific user"""
    other_user = User.query.get_or_404(user_id)
    
    # Handle sending new message
    if request.method == 'POST':
        content = request.form.get('message')
        if content and content.strip():
            message = Message(
                sender_id=current_user.id,
                recipient_id=user_id,
                content=content
            )
            db.session.add(message)
            db.session.commit()
            flash('Message sent!', 'success')
            return redirect(url_for('conversation', user_id=user_id))
    
    # Get all messages between the current user and the other user
    sent_messages = Message.query.filter_by(
        sender_id=current_user.id, 
        recipient_id=user_id
    ).order_by(Message.timestamp).all()
    
    received_messages = Message.query.filter_by(
        sender_id=user_id, 
        recipient_id=current_user.id
    ).order_by(Message.timestamp).all()
    
    # Mark received messages as read
    for message in received_messages:
        if not message.is_read:
            message.is_read = True
    
    db.session.commit()
    
    # Combine and sort all messages by timestamp
    all_messages = sorted(sent_messages + received_messages, key=lambda x: x.timestamp)
    
    return render_template(
        'messages/conversation.html',
        other_user=other_user,
        messages=all_messages
    )

@app.route('/messages/new', methods=['GET', 'POST'])
@login_required
def new_message():
    """Start a new conversation"""
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id')
        content = request.form.get('message')
        
        if not recipient_id or not content or not content.strip():
            flash('Both recipient and message are required.', 'danger')
            return redirect(url_for('new_message'))
        
        # Check if recipient exists
        recipient = User.query.get(recipient_id)
        if not recipient:
            flash('User not found.', 'danger')
            return redirect(url_for('new_message'))
        
        message = Message(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            content=content
        )
        
        db.session.add(message)
        db.session.commit()
        flash('Message sent!', 'success')
        return redirect(url_for('conversation', user_id=recipient_id))
    
    # Get friends list for dropdown
    friendships = Friendship.query.filter(
        (Friendship.user1_id == current_user.id) | (Friendship.user2_id == current_user.id)
    ).all()

    friends_list = []
    for friendship in friendships:
        if friendship.user1_id == current_user.id:
            friends_list.append(friendship.user2)
        else:
            friends_list.append(friendship.user1)
    
    return render_template('messages/new_message.html', friends=friends_list)

# Add this route to get unread message count for navbar badge
@app.route('/api/unread-count')
@login_required
def unread_count():
    count = Message.query.filter_by(
        recipient_id=current_user.id,
        is_read=False
    ).count()
    return {'count': count}



@app.route('/refresh_conversation/<int:user_id>')
@login_required
def refresh_conversation(user_id):
    other_user = User.query.get_or_404(user_id)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()
    return render_template('messages/conversation_messages.html', messages=messages)


def get_skill_similarity(user1, user2):
    """Calculate skill similarity between two users"""
    skills1 = set(user1.get_skills_list())
    skills2 = set(user2.get_skills_list())
    
    if not skills1 or not skills2:
        return 0
    
    # Jaccard similarity: intersection over union
    intersection = len(skills1.intersection(skills2))
    union = len(skills1.union(skills2))
    
    return intersection / union if union > 0 else 0

def get_skill_complementarity(user1, user2):
    """Calculate skill complementarity between two users"""
    skills1 = set(user1.get_skills_list())
    skills2 = set(user2.get_skills_list())
    
    if not skills1 or not skills2:
        return 0
    
    # Skills that user2 has that user1 doesn't
    complementary_skills = skills2.difference(skills1)
    
    # Normalize by the total possible new skills
    return len(complementary_skills) / len(skills2) if skills2 else 0

# Routes for skill-based suggestions
@app.route('/skill_suggestions')
@login_required
def skill_suggestions():
    # Get all users except current user
    users = User.query.filter(User.id != current_user.id).all()
    
    # Skip users with no skills
    if not current_user.skills:
        flash("Please add skills to your profile to get suggestions.", "info")
        return redirect(url_for('edit_profile'))
    
    similar_users = []
    complementary_users = []
    
    for user in users:
        if user.skills:  # Skip users with no skills
            similarity = get_skill_similarity(current_user, user)
            complementarity = get_skill_complementarity(current_user, user)
            
            similar_users.append((user, similarity))
            complementary_users.append((user, complementarity))
    
    # Sort by score (highest first)
    similar_users.sort(key=lambda x: x[1], reverse=True)
    complementary_users.sort(key=lambda x: x[1], reverse=True)
    
    # Take top 5 of each
    top_similar = similar_users[:5]
    top_complementary = complementary_users[:5]
    
    return render_template(
        'skill_suggestions.html',
        similar_users=top_similar,
        complementary_users=top_complementary
    )

# Add this route to find people with a specific skill
@app.route('/find_by_skill', methods=['GET', 'POST'])
@login_required
def find_by_skill():
    if request.method == 'POST':
        skill = request.form.get('skill').strip().lower()
        if not skill:
            flash("Please enter a skill to search for.", "warning")
            return redirect(url_for('find_by_skill'))
        
        # Find users with this skill
        users_with_skill = []
        all_users = User.query.filter(User.id != current_user.id).all()
        
        for user in all_users:
            if user.skills and skill in [s.strip().lower() for s in user.skills.split(',')]:
                users_with_skill.append(user)
        
        return render_template(
            'skill_search_results.html',
            users=users_with_skill,
            skill=skill
        )
    
    return render_template('find_by_skill.html')

# Add this route to suggest project teammates based on required skills
@app.route('/project/<int:project_id>/suggest_teammates')
@login_required
def suggest_project_teammates(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user is the owner
    if project.owner_id != current_user.id:
        flash("Only project owners can access team suggestions.", "warning")
        return redirect(url_for('project_page', project_id=project_id))
    
    # Get project skills (assuming you've added a skills field to Project model)
    if not project.tags:
        flash("Please add skill tags to your project to get suggestions.", "info")
        return redirect(url_for('edit_project', project_id=project_id))
    
    project_skills = [tag.strip().lower() for tag in project.tags.split(',')]
    
    # Find users who have these skills
    all_users = User.query.filter(User.id != current_user.id).all()
    suggested_teammates = []
    
    for user in all_users:
        if not user.skills:
            continue
        
        user_skills = [skill.strip().lower() for skill in user.skills.split(',')]
        matching_skills = set(project_skills).intersection(set(user_skills))
        
        if matching_skills:
            # Calculate match percentage
            match_percentage = (len(matching_skills) / len(project_skills)) * 100
            suggested_teammates.append({
                'user': user,
                'matching_skills': list(matching_skills),
                'match_percentage': match_percentage
            })
    
    # Sort by match percentage (highest first)
    suggested_teammates.sort(key=lambda x: x['match_percentage'], reverse=True)
    
    return render_template(
        'suggest_teammates.html',
        project=project,
        suggested_teammates=suggested_teammates
    )