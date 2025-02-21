from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

hashed_password = generate_password_hash("yourpassword")
print(hashed_password)  

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Chandu9106@localhost/goalplanner' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Modelscl
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)  


class Goal(db.Model):
    __tablename__ = 'goals'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    is_current = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/add_goal', methods=['POST'])
@login_required
def add_goal():
    goal_title = request.form.get('goal_title')
    if goal_title:
        new_goal = Goal(title=goal_title, user_id=current_user.id)
        db.session.add(new_goal)
        db.session.commit()
        flash('Goal added!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_goal', methods=['POST'])
@login_required
def update_goal():
    goal_id = request.form.get('goal_id')
    new_name = request.form.get('new_name')

    goal = Goal.query.filter_by(id=goal_id, user_id=current_user.id).first()
    if goal and new_name:
        goal.title = new_name
        db.session.commit()
        flash('Goal updated successfully!', 'success')

    return redirect(url_for('dashboard'))


@app.route('/delete_goal', methods=['POST'])
@login_required
def delete_goal():
    goal_id = request.form.get('goal_id')
    goal = Goal.query.filter_by(id=goal_id, user_id=current_user.id).first()

    if goal:
        db.session.delete(goal)
        db.session.commit()
        flash('Goal deleted!', 'success')

    return redirect(url_for('dashboard'))


@app.route('/complete_goal', methods=['POST'])
@login_required
def complete_goal():
    goal_id = request.form.get('goal_id')
    goal = Goal.query.get(goal_id)

    if goal and goal.user_id == current_user.id:
        goal.completed = True  # Mark as completed
        db.session.commit()
        flash("Goal marked as completed!", "success")

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_goals = Goal.query.filter_by(user_id=current_user.id).count() 
    completed_goals = Goal.query.filter_by(user_id=current_user.id, completed=True).count()  # Count completed goals

    progress_percentage = (completed_goals / total_goals * 100) if total_goals > 0 else 0

    current_goal = Goal.query.filter_by(user_id=current_user.id, is_current=True).first()

    return render_template('dashboard.html', 
                           goals=Goal.query.filter_by(user_id=current_user.id).all(),
                           total_goals=total_goals, 
                           completed_goals=completed_goals, 
                           progress_percentage=int(progress_percentage), 
                           current_goal=current_goal.title if current_goal else "No active goal")

@app.route('/login', methods=['GET', 'POST'])  
def login():
    if request.method == 'POST':
        username = request.form.get('username')  
        password = request.form.get('password')

        if not username or not password:
            flash('Please enter both username and password', 'danger')
            return redirect(url_for('login'))

        user_record = User.query.filter_by(username=username).first()

        if user_record and check_password_hash(user_record.password, password):
            login_user(user_record)  
            return redirect(url_for('dashboard'))

        flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST']) 
def signup():
    if request.method == 'POST':
        username = request.form.get('username') 
        password = request.form.get('password')

        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
