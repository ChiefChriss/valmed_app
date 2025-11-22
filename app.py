# app.py
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from models import db, User, Employee, Group, UserGroup, TaskStatus, Task, Department, Role, TaskComment, Notification

socketio = None


def create_app():
    global socketio
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    socketio = SocketIO(app, cors_allowed_origins="*")

    @app.cli.command("init-db")
    def init_db():
        """Initialize database and seed default data."""
        import random
        import string
        
        with app.app_context():
            db.drop_all()
            db.create_all()

            # Default statuses
            open_s = TaskStatus(label="Open", is_default=True)
            in_prog = TaskStatus(label="In-Progress")
            complete = TaskStatus(label="Complete", is_complete=True)
            db.session.add_all([open_s, in_prog, complete])

            # Default department/role (optional)
            dept = Department(name="General", description="Default Department")
            role = Role(name="Employee", description="Default Role")
            db.session.add_all([dept, role])

            # Admin user
            admin_user = User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                is_active=True
            )
            db.session.add(admin_user)
            db.session.flush()  # to get id

            # Employee tied to admin user with generated employee_id
            admin_emp = Employee(
                employee_id="EMP-00001",  # Fixed ID for admin
                first_name="System",
                last_name="Admin",
                department=dept,
                role=role,
                user=admin_user
            )
            db.session.add(admin_emp)

            # Admin group
            admin_group = Group(
                name="Admins",
                description="System administrators",
                is_admin_group=True
            )
            db.session.add(admin_group)
            db.session.flush()

            # Add admin user to admin group
            ug = UserGroup(user_id=admin_user.id, group_id=admin_group.id)
            db.session.add(ug)

            db.session.commit()
            print("Database initialized. Admin login: admin / admin123")
            print("Admin Employee ID: EMP-00001")

    @app.context_processor
    def inject_globals():
        user = None
        unread_count = 0
        if "user_id" in session:
            user = User.query.get(session["user_id"])
            if user:
                unread_count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
        return {'now_year': datetime.utcnow().year, 'current_user': user, 'unread_notifications': unread_count}

    # ---------- helper functions ----------
    
    def create_notification(user_id, title, message, notification_type, task_id=None):
        """Helper function to create notifications"""
        notif = Notification(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=notification_type,
            task_id=task_id,
            created_at=datetime.utcnow()
        )
        db.session.add(notif)
        db.session.flush()
        
        # Get updated unread count for this user
        unread_count = Notification.query.filter_by(
            user_id=user_id,
            is_read=False
        ).count()
        
        # Emit real-time notification via SocketIO
        if socketio:
            socketio.emit('new_notification', {
                'user_id': user_id,
                'title': title,
                'message': message,
                'type': notification_type,
                'task_id': task_id,
                'count': unread_count,  # Include count for instant badge update
                'created_at': notif.created_at.strftime('%b %d, %I:%M %p')
            }, room=f'user_{user_id}')

    # ---------- auth helpers ----------
    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                # AJAX request? Return JSON instead of redirect
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"error": "not authenticated"}), 401
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated

    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                # AJAX request? Return JSON instead of redirect
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"error": "not authenticated"}), 401
                return redirect(url_for("login"))
            user = User.query.get(session["user_id"])
            if not user or not user.is_admin():
                # AJAX request? Return JSON instead of redirect
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"error": "Admin access required"}), 403
                flash("Admin access required.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated

    # ---------- routes ----------

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session["user_id"] = user.id
                flash("Logged in successfully.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.", "danger")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = User.query.get(session["user_id"])
        
        # If user doesn't exist (deleted), clear session and redirect to login
        if not user:
            session.clear()
            flash("Your account no longer exists. Please contact an administrator.", "danger")
            return redirect(url_for("login"))
        
        # Tasks assigned directly to user OR to groups they belong to
        my_tasks = Task.query.filter(
            (Task.assigned_user_id == user.id) |
            (Task.assigned_group_id.in_([g.id for g in user.groups]))
        ).all()
        open_tasks = Task.query.count()
        employees_count = Employee.query.count()
        groups_count = Group.query.count()
        return render_template(
            "dashboard.html",
            user=user,
            my_tasks=my_tasks,
            open_tasks=open_tasks,
            employees_count=employees_count,
            groups_count=groups_count
        )

    # ---------- employee routes ----------

    @app.route("/employees")
    @login_required
    def employees():
        emps = Employee.query.all()
        departments = Department.query.all()
        roles = Role.query.all()
        return render_template("employees.html", employees=emps,
                               departments=departments, roles=roles)

    @app.route("/employees/add", methods=["POST"])
    @admin_required
    def add_employee():
        import random
        import string
        
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        address = request.form.get("address")
        try:
            salary_input = request.form.get("salary")
            salary = float(salary_input) if salary_input else 0.0
        except ValueError:
            salary = 0.0  # Default to 0 if they type garbage
        date_of_hire = request.form.get("date_of_hire") or None
        date_of_birth = request.form.get("date_of_birth") or None
        department_id = request.form.get("department_id") or None
        role_id = request.form.get("role_id") or None
        
        # Get username and password
        username = request.form.get("username")
        password = request.form.get("password") or "password123"
        
        # Validate username
        if not username:
            flash("Username is required.", "danger")
            return redirect(url_for("employees"))
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different username.", "danger")
            return redirect(url_for("employees"))
        
        # Generate unique employee ID (e.g., EMP-12345)
        def generate_employee_id():
            while True:
                emp_id = f"EMP-{''.join(random.choices(string.digits, k=5))}"
                if not Employee.query.filter_by(employee_id=emp_id).first():
                    return emp_id
        
        employee_id = generate_employee_id()
        
        # Check if admin privileges requested
        is_admin = bool(request.form.get("is_admin"))
        
        # Create user account
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            is_active=True
        )
        db.session.add(new_user)
        db.session.flush()  # Get user ID

        # If admin privileges requested, add to Admins group
        if is_admin:
            admin_group = Group.query.filter_by(is_admin_group=True).first()
            if admin_group:
                ug = UserGroup(user_id=new_user.id, group_id=admin_group.id)
                db.session.add(ug)

        # Create employee
        emp = Employee(
            employee_id=employee_id,
            first_name=first_name,
            last_name=last_name,
            address=address,
            salary=salary,
            date_of_hire=datetime.strptime(date_of_hire, "%Y-%m-%d") if date_of_hire else None,
            date_of_birth=datetime.strptime(date_of_birth, "%Y-%m-%d") if date_of_birth else None,
            department_id=department_id,
            role_id=role_id,
            user_id=new_user.id
        )
        db.session.add(emp)
        db.session.commit()
        
        admin_msg = " with Admin privileges" if is_admin else ""
        flash(f"Employee added successfully{admin_msg}! Employee ID: {employee_id}, Username: {username}", "success")
        return redirect(url_for("employees"))

    @app.route("/employees/<int:employee_id>/edit", methods=["POST"])
    @admin_required
    def edit_employee(employee_id):
        emp = Employee.query.get_or_404(employee_id)
        
        emp.first_name = request.form.get("first_name")
        emp.last_name = request.form.get("last_name")
        emp.address = request.form.get("address")
        
        salary_str = request.form.get("salary")
        try:
            emp.salary = float(salary_str) if salary_str else None
        except ValueError:
            emp.salary = None  # Default to None if they type garbage
        
        date_of_hire = request.form.get("date_of_hire")
        emp.date_of_hire = datetime.strptime(date_of_hire, "%Y-%m-%d") if date_of_hire else None
        
        date_of_birth = request.form.get("date_of_birth")
        emp.date_of_birth = datetime.strptime(date_of_birth, "%Y-%m-%d") if date_of_birth else None
        
        department_id = request.form.get("department_id")
        emp.department_id = int(department_id) if department_id else None
        
        role_id = request.form.get("role_id")
        emp.role_id = int(role_id) if role_id else None
        
        # Update user account info if exists
        if emp.user:
            new_username = request.form.get("username")
            if new_username and new_username != emp.user.username:
                # Check if username already taken
                existing = User.query.filter_by(username=new_username).first()
                if existing and existing.id != emp.user.id:
                    flash("Username already taken. Please choose another.", "danger")
                    return redirect(url_for("employees"))
                emp.user.username = new_username
            
            # Update account status
            is_active = request.form.get("is_active")
            emp.user.is_active = bool(int(is_active)) if is_active else True
        
        db.session.commit()
        flash(f"Employee {emp.full_name()} updated successfully.", "success")
        return redirect(url_for("employees"))

    @app.route("/employees/<int:employee_id>/reset_password", methods=["POST"])
    @admin_required
    def reset_employee_password(employee_id):
        emp = Employee.query.get_or_404(employee_id)
        
        if not emp.user:
            flash("Employee does not have a user account.", "danger")
            return redirect(url_for("employees"))
        
        new_password = request.form.get("new_password")
        if not new_password:
            flash("Password cannot be empty.", "danger")
            return redirect(url_for("employees"))
        
        emp.user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash(f"Password reset successfully for {emp.full_name()}.", "success")
        return redirect(url_for("employees"))

    @app.route("/employees/<int:employee_id>/delete", methods=["POST"])
    @admin_required
    def delete_employee(employee_id):
        emp = Employee.query.get_or_404(employee_id)
        emp_name = emp.full_name()
        db.session.delete(emp)
        db.session.commit()
        flash(f"Employee {emp_name} has been deleted.", "info")
        return redirect(url_for("employees"))

    @app.route("/employees/<int:employee_id>/toggle_admin", methods=["POST"])
    @admin_required
    def toggle_employee_admin(employee_id):
        emp = Employee.query.get_or_404(employee_id)
        
        if not emp.user:
            flash("Employee must have a user account to grant admin privileges.", "danger")
            return redirect(url_for("employees"))
        
        # Protect System Admin (username: admin or employee_id: EMP-00001)
        if emp.user.username == "admin" or emp.employee_id == "EMP-00001":
            flash("Cannot modify System Admin privileges.", "danger")
            return redirect(url_for("employees"))
        
        # Get or create admin group
        admin_group = Group.query.filter_by(is_admin_group=True).first()
        if not admin_group:
            flash("Admin group not found. Please create one first.", "danger")
            return redirect(url_for("employees"))
        
        # Check if user is already admin
        is_currently_admin = emp.user.is_admin()
        
        if is_currently_admin:
            # Remove from admin group
            ug = UserGroup.query.filter_by(user_id=emp.user.id, group_id=admin_group.id).first()
            if ug:
                db.session.delete(ug)
                db.session.commit()
                flash(f"Admin privileges revoked from {emp.full_name()}.", "info")
        else:
            # Add to admin group
            ug = UserGroup.query.filter_by(user_id=emp.user.id, group_id=admin_group.id).first()
            if not ug:
                db.session.add(UserGroup(user_id=emp.user.id, group_id=admin_group.id))
                db.session.commit()
                flash(f"Admin privileges granted to {emp.full_name()}.", "success")
        
        return redirect(url_for("employees"))

    # ---------- department & role routes ----------

    @app.route("/departments_roles")
    @admin_required
    def departments_roles():
        depts = Department.query.all()
        roles = Role.query.all()
        return render_template("departments_roles.html", departments=depts, roles=roles)

    @app.route("/departments/add", methods=["POST"])
    @admin_required
    def add_department():
        name = request.form.get("name")
        description = request.form.get("description")
        if name:
            db.session.add(Department(name=name, description=description))
            db.session.commit()
            flash("Department added.", "success")
        return redirect(url_for("departments_roles"))

    @app.route("/departments/<int:dept_id>/edit", methods=["POST"])
    @admin_required
    def edit_department(dept_id):
        dept = Department.query.get_or_404(dept_id)
        dept.name = request.form.get("name")
        dept.description = request.form.get("description")
        db.session.commit()
        flash("Department updated.", "success")
        return redirect(url_for("departments_roles"))

    @app.route("/departments/<int:dept_id>/delete", methods=["POST"])
    @admin_required
    def delete_department(dept_id):
        dept = Department.query.get_or_404(dept_id)
        if dept.employees:
            flash("Cannot delete department with assigned employees.", "danger")
        else:
            db.session.delete(dept)
            db.session.commit()
            flash("Department deleted.", "success")
        return redirect(url_for("departments_roles"))

    @app.route("/roles/add", methods=["POST"])
    @admin_required
    def add_role():
        name = request.form.get("name")
        description = request.form.get("description")
        if name:
            db.session.add(Role(name=name, description=description))
            db.session.commit()
            flash("Role added.", "success")
        return redirect(url_for("departments_roles"))

    @app.route("/roles/<int:role_id>/edit", methods=["POST"])
    @admin_required
    def edit_role(role_id):
        role = Role.query.get_or_404(role_id)
        role.name = request.form.get("name")
        role.description = request.form.get("description")
        db.session.commit()
        flash("Role updated.", "success")
        return redirect(url_for("departments_roles"))

    @app.route("/roles/<int:role_id>/delete", methods=["POST"])
    @admin_required
    def delete_role(role_id):
        role = Role.query.get_or_404(role_id)
        if role.employees:
            flash("Cannot delete role with assigned employees.", "danger")
        else:
            db.session.delete(role)
            db.session.commit()
            flash("Role deleted.", "success")
        return redirect(url_for("departments_roles"))

    # ---------- group routes ----------

    @app.route("/groups")
    @login_required
    def groups():
        all_groups = Group.query.all()
        users = User.query.all()
        employees = Employee.query.all()
        return render_template("groups.html", groups=all_groups, users=users, employees=employees)

    @app.route("/groups/add", methods=["POST"])
    @admin_required
    def add_group():
        name = request.form.get("name")
        description = request.form.get("description")
        is_admin_group = bool(request.form.get("is_admin_group"))

        g = Group(name=name, description=description, is_admin_group=is_admin_group)
        db.session.add(g)
        db.session.commit()
        flash("Group created.", "success")
        return redirect(url_for("groups"))

    @app.route("/groups/<int:group_id>/edit", methods=["POST"])
    @admin_required
    def edit_group(group_id):
        group = Group.query.get_or_404(group_id)
        group.name = request.form.get("name")
        group.description = request.form.get("description")
        group.is_admin_group = bool(request.form.get("is_admin_group"))
        db.session.commit()
        flash(f"Group '{group.name}' updated successfully.", "success")
        return redirect(url_for("groups"))

    @app.route("/groups/<int:group_id>/delete", methods=["POST"])
    @admin_required
    def delete_group(group_id):
        group = Group.query.get_or_404(group_id)
        group_name = group.name
        db.session.delete(group)
        db.session.commit()
        flash(f"Group '{group_name}' has been deleted.", "info")
        return redirect(url_for("groups"))

    @app.route("/groups/<int:group_id>/remove_user/<int:user_id>", methods=["POST"])
    @admin_required
    def remove_user_from_group(group_id, user_id):
        ug = UserGroup.query.filter_by(user_id=user_id, group_id=group_id).first()
        if ug:
            db.session.delete(ug)
            db.session.commit()
            flash("User removed from group.", "success")
        else:
            flash("User not found in group.", "warning")
        return redirect(url_for("groups"))

    @app.route("/groups/<int:group_id>/add_user", methods=["POST"])
    @admin_required
    def add_user_to_group(group_id):
        employee_id = request.form.get("employee_id")
        if employee_id:
            emp = Employee.query.get_or_404(employee_id)
            
            # If employee has no user account, create one
            if not emp.user:
                base_username = f"{emp.first_name.lower()}.{emp.last_name.lower()}"
                username = base_username
                counter = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1
                
                new_user = User(
                    username=username,
                    password_hash=generate_password_hash("password123"),
                    is_active=True
                )
                db.session.add(new_user)
                db.session.flush()
                emp.user = new_user
                flash(f"Created user account '{username}' for {emp.full_name()}", "info")
            
            user = emp.user
            exists = UserGroup.query.filter_by(user_id=user.id, group_id=group_id).first()
            if not exists:
                db.session.add(UserGroup(user_id=user.id, group_id=group_id))
                db.session.commit()
                flash("User added to group.", "success")
            else:
                flash("User already in group.", "info")
        return redirect(url_for("groups"))

    # ---------- task status routes ----------

    @app.route("/statuses")
    @admin_required
    def statuses():
        statuses = TaskStatus.query.all()
        return render_template("statuses.html", statuses=statuses)

    @app.route("/statuses/add", methods=["POST"])
    @admin_required
    def add_status():
        label = request.form.get("label")
        is_default = bool(request.form.get("is_default"))
        if is_default:
            # unset previous defaults
            TaskStatus.query.update({TaskStatus.is_default: False})
        s = TaskStatus(label=label, is_default=is_default)
        db.session.add(s)
        db.session.commit()
        flash("Status added.", "success")
        return redirect(url_for("statuses"))

    @app.route("/statuses/<int:status_id>/edit", methods=["POST"])
    @admin_required
    def edit_status(status_id):
        status = TaskStatus.query.get_or_404(status_id)
        status.label = request.form.get("label")
        is_default = bool(request.form.get("is_default"))
        
        if is_default:
             TaskStatus.query.update({TaskStatus.is_default: False})
             status.is_default = True
        else:
             status.is_default = False
             
        db.session.commit()
        flash("Status updated.", "success")
        return redirect(url_for("statuses"))

    @app.route("/statuses/<int:status_id>/delete", methods=["POST"])
    @admin_required
    def delete_status(status_id):
        status = TaskStatus.query.get_or_404(status_id)
        if status.tasks:
            flash("Cannot delete status that is assigned to tasks.", "danger")
        else:
            db.session.delete(status)
            db.session.commit()
            flash("Status deleted.", "success")
        return redirect(url_for("statuses"))

    # ---------- task routes ----------

    @app.route("/tasks")
    @login_required
    def tasks():
        user = User.query.get(session["user_id"])
        
        # Admins see all tasks
        if user.is_admin():
            tasks = Task.query.order_by(Task.created_at.desc()).all()
        else:
            # Regular employees only see:
            # 1. Tasks assigned to them directly
            # 2. Tasks assigned to groups they belong to
            # 3. Tasks they created
            group_ids = [g.id for g in user.groups]
            tasks = Task.query.filter(
                (Task.assigned_user_id == user.id) |
                (Task.assigned_group_id.in_(group_ids)) |
                (Task.created_by_user_id == user.id)
            ).order_by(Task.created_at.desc()).all()
        
        users = User.query.all()
        groups = Group.query.all()
        statuses = TaskStatus.query.all()
        return render_template(
            "tasks.html",
            tasks=tasks,
            users=users,
            groups=groups,
            statuses=statuses
        )

    @app.route("/tasks/add", methods=["POST"])
    @login_required
    def add_task():
        user = User.query.get(session["user_id"])
        title = request.form.get("title")
        description = request.form.get("description")
        
        # Only admins can assign tasks to others
        if user.is_admin():
            assigned_user_id = request.form.get("assigned_user_id") or None
            assigned_group_id = request.form.get("assigned_group_id") or None
        else:
            # Regular users can only assign to themselves (or leave unassigned if that's the logic, 
            # but usually they create tasks for themselves)
            assigned_user_id = user.id
            assigned_group_id = None

        status_id = request.form.get("status_id") or None
        due_date = request.form.get("due_date") or None

        if not status_id:
            default_status = TaskStatus.query.filter_by(is_default=True).first()
            status_id = default_status.id if default_status else None

        task = Task(
            title=title,
            description=description,
            status_id=status_id,
            assigned_user_id=assigned_user_id,
            assigned_group_id=assigned_group_id,
            created_by_user_id=user.id,
            created_at=datetime.utcnow(),
            due_date=datetime.strptime(due_date, "%Y-%m-%d").date() if due_date else None
        )
        db.session.add(task)
        db.session.flush()  # Get task ID
        
        # Create notifications
        # 1. Notify assigned user
        if assigned_user_id and assigned_user_id != user.id:
            create_notification(
                assigned_user_id,
                "New Task Assigned",
                f"You have been assigned to task: {title}",
                "task_assigned",
                task.id
            )
        
        # 2. Notify group members
        if assigned_group_id:
            group = Group.query.get(assigned_group_id)
            if group:
                for member in group.users:
                    if member.id != user.id:  # Don't notify creator
                        create_notification(
                            member.id,
                            "New Group Task",
                            f"New task for {group.name}: {title}",
                            "group_task",
                            task.id
                        )
        
        db.session.commit()
        flash("Task created.", "success")
        return redirect(url_for("tasks"))

    @app.route("/tasks/<int:task_id>/update_status", methods=["POST"])
    @login_required
    def update_task_status(task_id):
        user = User.query.get(session["user_id"])
        status_id = request.form.get("status_id")
        
        # Validate status_id
        if not status_id:
            return jsonify({"error": "Missing status_id"}), 400
        
        task = Task.query.get(task_id)
        if not task:
            return jsonify({"error": "Task not found"}), 404
        
        try:
            status_id = int(status_id)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid status_id"}), 400
        
        old_status = task.status.label if task.status else "None"
        task.status_id = status_id

        # if marked complete, set completed_at
        status = TaskStatus.query.get(status_id)
        if not status:
            return jsonify({"error": "Status not found"}), 400
            
        if status.is_complete:
            task.completed_at = datetime.utcnow()
        
        # Notify relevant users about status change
        new_status_label = status.label
        
        # Notify task creator if they didn't make the change
        if task.created_by_user_id != user.id:
            create_notification(
                task.created_by_user_id,
                "Task Status Changed",
                f"Task '{task.title}' status changed from {old_status} to {new_status_label}",
                "status_changed",
                task.id
            )
        
        # Notify assignee if they didn't make the change
        if task.assigned_user_id and task.assigned_user_id != user.id:
            create_notification(
                task.assigned_user_id,
                "Task Status Changed",
                f"Task '{task.title}' status changed to {new_status_label}",
                "status_changed",
                task.id
            )
        
        db.session.commit()
        
        # Emit live update to all connected clients
        if socketio:
            socketio.emit('task_moved', {
                'task_id': task.id,
                'new_status_id': status_id,
                'status_label': new_status_label,
                'task_title': task.title
            }, broadcast=True)
        
        # Return JSON for AJAX requests, redirect for form submissions
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": True, "message": "Task status updated."}), 200
        else:
            flash("Task status updated.", "success")
            return redirect(url_for("tasks"))

    @app.route("/tasks/<int:task_id>/mark_complete", methods=["POST"])
    @login_required
    def mark_task_complete(task_id):
        task = Task.query.get_or_404(task_id)
        complete_status = TaskStatus.query.filter(
            TaskStatus.is_complete == True
        ).first()
        if complete_status:
            task.status = complete_status
        task.completed_at = datetime.utcnow()
        db.session.commit()
        flash("Task marked complete.", "success")
        return redirect(url_for("tasks"))

    # ---------- task comment routes ----------

    @app.route("/tasks/<int:task_id>/view")
    @login_required
    def view_task(task_id):
        task = Task.query.get_or_404(task_id)
        user = User.query.get(session["user_id"])
        can_comment = task.can_comment(user)
        statuses = TaskStatus.query.all()
        return render_template("task_detail.html", task=task, can_comment=can_comment, statuses=statuses)

    @app.route("/tasks/<int:task_id>/comment", methods=["POST"])
    @login_required
    def add_task_comment(task_id):
        task = Task.query.get_or_404(task_id)
        user = User.query.get(session["user_id"])
        
        # Check permission
        if not task.can_comment(user):
            flash("You don't have permission to comment on this task.", "danger")
            return redirect(url_for("view_task", task_id=task_id))
        
        content = request.form.get("content")
        if not content or not content.strip():
            flash("Comment cannot be empty.", "warning")
            return redirect(url_for("view_task", task_id=task_id))
        
        comment = TaskComment(
            task_id=task_id,
            user_id=user.id,
            content=content.strip(),
            created_at=datetime.utcnow()
        )
        db.session.add(comment)
        
        # Notify relevant users about new comment
        notified_users = set()
        
        # Notify task creator
        if task.created_by_user_id != user.id:
            create_notification(
                task.created_by_user_id,
                "New Comment",
                f"{user.username} commented on '{task.title}'",
                "comment_added",
                task.id
            )
            notified_users.add(task.created_by_user_id)
        
        # Notify assignee
        if task.assigned_user_id and task.assigned_user_id != user.id and task.assigned_user_id not in notified_users:
            create_notification(
                task.assigned_user_id,
                "New Comment",
                f"{user.username} commented on '{task.title}'",
                "comment_added",
                task.id
            )
            notified_users.add(task.assigned_user_id)
        
        # Notify group members
        if task.assigned_group:
            for member in task.assigned_group.users:
                if member.id != user.id and member.id not in notified_users:
                    create_notification(
                        member.id,
                        "New Comment",
                        f"{user.username} commented on group task '{task.title}'",
                        "comment_added",
                        task.id
                    )
                    notified_users.add(member.id)
        
        db.session.commit()
        flash("Comment added successfully.", "success")
        return redirect(url_for("view_task", task_id=task_id))

    @app.route("/tasks/<int:task_id>/comment/<int:comment_id>/edit", methods=["POST"])
    @login_required
    def edit_task_comment(task_id, comment_id):
        comment = TaskComment.query.get_or_404(comment_id)
        user = User.query.get(session["user_id"])
        
        # Only comment author or admin can edit
        if comment.user_id != user.id and not user.is_admin():
            flash("You don't have permission to edit this comment.", "danger")
            return redirect(url_for("view_task", task_id=task_id))
        
        content = request.form.get("content")
        if content and content.strip():
            comment.content = content.strip()
            comment.updated_at = datetime.utcnow()
            db.session.commit()
            flash("Comment updated successfully.", "success")
        
        return redirect(url_for("view_task", task_id=task_id))

    @app.route("/tasks/<int:task_id>/comment/<int:comment_id>/delete", methods=["POST"])
    @login_required
    def delete_task_comment(task_id, comment_id):
        comment = TaskComment.query.get_or_404(comment_id)
        user = User.query.get(session["user_id"])
        
        # Only comment author or admin can delete
        if comment.user_id != user.id and not user.is_admin():
            flash("You don't have permission to delete this comment.", "danger")
            return redirect(url_for("view_task", task_id=task_id))
        
        db.session.delete(comment)
        db.session.commit()
        flash("Comment deleted successfully.", "info")
        return redirect(url_for("view_task", task_id=task_id))

    @app.route("/tasks/<int:task_id>/delete", methods=["POST"])
    @admin_required
    def delete_task(task_id):
        task = Task.query.get_or_404(task_id)
        task_title = task.title
        db.session.delete(task)
        db.session.commit()
        flash(f"Task '{task_title}' has been deleted.", "info")
        return redirect(url_for("tasks"))

    # ---------- notification routes ----------

    @app.route("/notifications")
    @login_required
    def notifications():
        user = User.query.get(session["user_id"])
        all_notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
        return render_template("notifications.html", notifications=all_notifications)

    @app.route("/notifications/<int:notif_id>/mark_read", methods=["POST"])
    @login_required
    def mark_notification_read(notif_id):
        notif = Notification.query.get_or_404(notif_id)
        user = User.query.get(session["user_id"])
        
        if notif.user_id != user.id:
            flash("Unauthorized.", "danger")
            return redirect(url_for("notifications"))
        
        notif.is_read = True
        db.session.commit()
        
        # If notification has a task, redirect to it
        if notif.task_id:
            return redirect(url_for("view_task", task_id=notif.task_id))
        return redirect(url_for("notifications"))

    @app.route("/notifications/mark_all_read", methods=["POST"])
    @login_required
    def mark_all_notifications_read():
        user = User.query.get(session["user_id"])
        Notification.query.filter_by(user_id=user.id, is_read=False).update({Notification.is_read: True})
        db.session.commit()
        flash("All notifications marked as read.", "success")
        return redirect(url_for("notifications"))

    @app.route("/notifications/unread_count")
    @login_required
    def unread_notification_count():
        """API endpoint for polling unread count"""
        user = User.query.get(session["user_id"])
        count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
        return {"count": count}

    @app.route("/notifications/recent")
    @login_required
    def recent_notifications():
        """API endpoint for recent notifications"""
        user = User.query.get(session["user_id"])
        notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(5).all()
        
        return {
            "notifications": [
                {
                    "id": n.id,
                    "title": n.title,
                    "message": n.message,
                    "type": n.notification_type,
                    "task_id": n.task_id,
                    "is_read": n.is_read,
                    "created_at": n.created_at.strftime('%b %d, %I:%M %p') if n.created_at else ""
                }
                for n in notifications
            ]
        }

    # ---------- calendar routes ----------

    @app.route("/calendar")
    @login_required
    def calendar():
        return render_template("calendar.html")

    @app.route("/calendar/events")
    @login_required
    def calendar_events():
        """API endpoint for FullCalendar events"""
        user = User.query.get(session["user_id"])
        
        # Get tasks visible to user
        if user.is_admin():
            tasks = Task.query.all()
        else:
            group_ids = [g.id for g in user.groups]
            tasks = Task.query.filter(
                (Task.assigned_user_id == user.id) |
                (Task.assigned_group_id.in_(group_ids)) |
                (Task.created_by_user_id == user.id)
            ).all()
        
        events = []
        for task in tasks:
            if task.due_date:
                # Determine color based on status
                color = "#6c757d"  # default gray
                if task.status:
                    if task.status.is_complete:
                        color = "#28a745"  # green
                    elif task.status.label.lower() == "in-progress":
                        color = "#ffc107"  # yellow
                    else:
                        color = "#0d6efd"  # blue
                
                events.append({
                    "id": task.id,
                    "title": task.title,
                    "start": task.due_date.strftime('%Y-%m-%d'),
                    "url": url_for('view_task', task_id=task.id),
                    "backgroundColor": color,
                    "borderColor": color,
                    "extendedProps": {
                        "status": task.status.label if task.status else "None",
                        "assignee": task.assignee.username if task.assignee else "Unassigned"
                    }
                })
        
        return events

    # ---------- socketio event handlers ----------
    
    @socketio.on('connect')
    def handle_connect():
        if 'user_id' in session:
            user_id = session['user_id']
            join_room(f'user_{user_id}')
            print(f"User {user_id} connected to their notification room")
    
    @socketio.on('disconnect')
    def handle_disconnect():
        if 'user_id' in session:
            user_id = session['user_id']
            leave_room(f'user_{user_id}')
            print(f"User {user_id} disconnected from their notification room")
    
    return app


if __name__ == "__main__":
    app = create_app()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
