# models.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Association table: many-to-many between users and groups
class UserGroup(db.Model):
    __tablename__ = "user_groups"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("groups.id"), primary_key=True)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    employee = db.relationship("Employee", back_populates="user", uselist=False)
    groups = db.relationship("Group", secondary="user_groups", back_populates="users")
    created_tasks = db.relationship("Task", back_populates="creator", foreign_keys="Task.created_by_user_id")
    notifications = db.relationship("Notification", back_populates="user", order_by="Notification.created_at.desc()")

    def is_admin(self):
        # Admin if in any group marked as admin
        return any(g.is_admin_group for g in self.groups)


class Department(db.Model):
    __tablename__ = "departments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    employees = db.relationship("Employee", back_populates="department")


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    employees = db.relationship("Employee", back_populates="role")


class Employee(db.Model):
    __tablename__ = "employees"

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)  # Random employee ID
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text)
    salary = db.Column(db.Float)

    date_of_hire = db.Column(db.Date)
    date_of_birth = db.Column(db.Date)

    department_id = db.Column(db.Integer, db.ForeignKey("departments.id"))
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    department = db.relationship("Department", back_populates="employees")
    role = db.relationship("Role", back_populates="employees")
    user = db.relationship("User", back_populates="employee")

    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class Group(db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    is_admin_group = db.Column(db.Boolean, default=False)

    users = db.relationship("User", secondary="user_groups", back_populates="groups")
    tasks = db.relationship("Task", back_populates="assigned_group")


class TaskStatus(db.Model):
    __tablename__ = "task_statuses"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(50), unique=True, nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    is_complete = db.Column(db.Boolean, default=False)

    tasks = db.relationship("Task", back_populates="status")


class Task(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)

    status_id = db.Column(db.Integer, db.ForeignKey("task_statuses.id"))
    assigned_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    assigned_group_id = db.Column(db.Integer, db.ForeignKey("groups.id"), nullable=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    created_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime, nullable=True)
    due_date = db.Column(db.Date, nullable=True)

    status = db.relationship("TaskStatus", back_populates="tasks")
    assignee = db.relationship("User", foreign_keys=[assigned_user_id])
    assigned_group = db.relationship("Group", back_populates="tasks")
    creator = db.relationship("User", back_populates="created_tasks", foreign_keys=[created_by_user_id])
    comments = db.relationship("TaskComment", back_populates="task", order_by="TaskComment.created_at", cascade="all, delete-orphan")

    def can_comment(self, user):
        """Check if user can comment on this task"""
        if user.is_admin():
            return True
        if self.created_by_user_id == user.id:
            return True
        if self.assigned_user_id == user.id:
            return True
        # Check if user is in assigned group
        if self.assigned_group and user in self.assigned_group.users:
            return True
        return False


class TaskComment(db.Model):
    __tablename__ = "task_comments"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    updated_at = db.Column(db.DateTime)

    task = db.relationship("Task", back_populates="comments")
    user = db.relationship("User")


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50))  # task_assigned, status_changed, comment_added, group_task
    task_id = db.Column(db.Integer, db.ForeignKey("tasks.id"), nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship("User")
    task = db.relationship("Task")
