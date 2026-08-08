from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort
from app.models import db, User, ActivityLog, BlockedIP
from app.routes.auth import admin_required
from app.services.telemetry import get_live_telemetry
from app.services.events import event_bus

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@admin_required
def dashboard():
    users = User.query.all()
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(100).all()
    blocked_ips = BlockedIP.query.all()
    telemetry = get_live_telemetry()
    
    # Simple metrics aggregation for UI display
    metrics = {
        'total_users': len(users),
        'blocked_users': sum(1 for u in users if u.is_blocked),
        'total_logs': ActivityLog.query.count(),
        'average_risk': db.session.query(db.func.avg(ActivityLog.risk_score)).scalar() or 0.0,
        'blocked_ips_count': len(blocked_ips),
        'telemetry': telemetry
    }
    
    return render_template(
        'admin.html',
        users=users,
        logs=logs,
        blocked_ips=blocked_ips,
        metrics=metrics
    )

@admin_bp.route('/block-user/<int:user_id>', methods=['POST'])
@admin_required
def block_user(user_id):
    if user_id == g.user.id:
        flash("You cannot block your own administrative account.", "warning")
        return redirect(url_for('admin.dashboard'))
        
    user = User.query.get_or_404(user_id)
    user.is_blocked = True
    
    # Save log
    db.session.add(ActivityLog(
        action='user_blocked',
        user_id=g.user.id,
        ip_address=request.remote_addr,
        risk_score=0.0,
        details=f"Admin blocked user: {user.email}"
    ))
    db.session.commit()
    
    flash(f"User '{user.username}' has been successfully blocked.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/unblock-user/<int:user_id>', methods=['POST'])
@admin_required
def unblock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_blocked = False
    
    # Save log
    db.session.add(ActivityLog(
        action='user_unblocked',
        user_id=g.user.id,
        ip_address=request.remote_addr,
        risk_score=0.0,
        details=f"Admin unblocked user: {user.email}"
    ))
    db.session.commit()
    
    flash(f"User '{user.username}' has been successfully unblocked.", "success")
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
    
    # Save log
    db.session.add(ActivityLog(
        action='user_role_change',
        user_id=g.user.id,
        ip_address=request.remote_addr,
        risk_score=0.0,
        details=f"Admin changed role of {user.email} to {new_role}"
    ))
    db.session.commit()
    
    flash(f"Role for '{user.username}' updated to '{new_role}'.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/block-ip', methods=['POST'])
@admin_required
def block_ip():
    ip_address = request.form.get('ip_address', '').strip()
    reason = request.form.get('reason', '').strip() or "Manual Administrator Block"
    
    if not ip_address:
        flash("IP address is required.", "warning")
        return redirect(url_for('admin.dashboard'))
        
    if ip_address in ['127.0.0.1', '::1', 'localhost']:
        flash("Bypassed: Blocking localhost could lock you out.", "warning")
        return redirect(url_for('admin.dashboard'))
        
    # Trigger IP Block event (uses the decoupled security block handler)
    event_bus.dispatch('security.block_ip', ip_address=ip_address, reason=reason)
    flash(f"IP address '{ip_address}' has been added to the firewall blocklist.", "success")
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/unblock-ip/<int:ip_id>', methods=['POST'])
@admin_required
def unblock_ip(ip_id):
    blocked_ip = BlockedIP.query.get_or_404(ip_id)
    ip_addr = blocked_ip.ip_address
    
    db.session.delete(blocked_ip)
    
    # Save log
    db.session.add(ActivityLog(
        action='ip_unblocked',
        user_id=g.user.id,
        ip_address=request.remote_addr,
        risk_score=0.0,
        details=f"Admin unblocked IP: {ip_addr}"
    ))
    db.session.commit()
    
    flash(f"IP address '{ip_addr}' has been successfully unblocked.", "success")
    return redirect(url_for('admin.dashboard'))
