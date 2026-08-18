from flask import Blueprint, render_template, request, redirect, url_for, flash, g
from app.models import db, User, ActivityLog
from app.routes.auth import admin_required

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@admin_required
def dashboard():
    users = User.query.all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()

    # Aggregated stats for the admin page
    metrics = {
        'total_users': len(users),
        'blocked_users': sum(1 for u in users if u.is_blocked),
        'total_logs': ActivityLog.query.count(),
    }

    return render_template(
        'admin.html',
        users=users,
        logs=logs,
        metrics=metrics
    )

@admin_bp.route('/block-user/<int:user_id>', methods=['POST'])
@admin_required
def block_user(user_id):
    if user_id == g.user.id:
        flash("You cannot deactivate your own administrative account.", "warning")
        return redirect(url_for('admin.dashboard'))

    user = User.query.get_or_404(user_id)
    user.is_blocked = True

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    # Save log
    db.session.add(ActivityLog(
        action='user_blocked',
        user_id=g.user.id,
        username=g.user.username,
        ip_address=ip or 'Unknown',
        details=f"Admin blocked user account: {user.email}"
    ))
    db.session.commit()

    flash(f"User '{user.username}' has been successfully blocked.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/unblock-user/<int:user_id>', methods=['POST'])
@admin_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_blocked = False

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    # Save log
    db.session.add(ActivityLog(
        action='user_unblocked',
        user_id=g.user.id,
        username=g.user.username,
        ip_address=ip or 'Unknown',
        details=f"Admin activated user account: {user.email}"
    ))
    db.session.commit()

    flash(f"User '{user.username}' has been successfully activated.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/change-role/<int:user_id>', methods=['POST'])
@admin_required
def change_role(user_id):
    if user_id == g.user.id:
        flash("You cannot revoke your own administrative privileges.", "warning")
        return redirect(url_for('admin.dashboard'))

    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ['user', 'admin']:
        flash("Invalid role assignment request.", "danger")
        return redirect(url_for('admin.dashboard'))

    user.role = new_role

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    # Save log
    db.session.add(ActivityLog(
        action='user_role_change',
        user_id=g.user.id,
        username=g.user.username,
        ip_address=ip or 'Unknown',
        details=f"Admin updated role of {user.email} to {new_role}"
    ))
    db.session.commit()

    flash(f"Role for '{user.username}' updated to '{new_role}'.", "success")
    return redirect(url_for('admin.dashboard'))
