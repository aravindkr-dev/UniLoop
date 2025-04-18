from app import *

@app.route('/my-projects')
@login_required
def my_projects():
    user_projects = Project.query.filter_by(owner_id=current_user.id).all()
    return render_template('project/dashboard.html', projects=user_projects)

@app.route('/create-project', methods=['GET', 'POST'])
@login_required
def create_project():
    # form logic to add project
    ...

@app.route('/project/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    # logic to edit project
    ...

@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    # logic to delete project
    ...
