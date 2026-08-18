import os
import json
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, send_file, abort, current_app
from sqlalchemy import func
from app.models import db, File, ActivityLog, Prediction
from app.routes.auth import login_required
from app.services.storage import save_file_to_disk, delete_file_from_disk, get_disk_file_path

logger = logging.getLogger(__name__)
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if g.user:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # 1. Fetch user files
    search_query = request.args.get('search', '').strip()
    file_query = File.query.filter_by(user_id=g.user.id, is_deleted=False)
    if search_query:
        file_query = file_query.filter(File.filename.like(f"%{search_query}%"))
    files = file_query.order_by(File.upload_time.desc()).all()

    # Storage metrics
    total_used_bytes = sum(file.file_size for file in File.query.filter_by(user_id=g.user.id, is_deleted=False).all())
    storage_limit_bytes = 100 * 1024 * 1024  # 100MB Demo Storage Limit
    used_percentage = min(100.0, (total_used_bytes / storage_limit_bytes) * 100)

    # 2. Fetch User Predictions Summary
    predictions_query = Prediction.query.filter_by(user_id=g.user.id)
    total_predictions = predictions_query.count()

    avg_confidence = db.session.query(func.avg(Prediction.confidence)).filter_by(user_id=g.user.id).scalar() or 0.0
    avg_confidence = round(float(avg_confidence), 1)

    recent_predictions = predictions_query.order_by(Prediction.timestamp.desc()).limit(10).all()

    # Class distribution aggregation
    dist_query = db.session.query(Prediction.prediction_class, func.count(Prediction.id))\
        .filter_by(user_id=g.user.id)\
        .group_by(Prediction.prediction_class).all()
    prediction_distribution = {cls: count for cls, count in dist_query}

    # 3. Retrieve Activity Audits
    timeline_logs = ActivityLog.query.filter_by(user_id=g.user.id).order_by(
        ActivityLog.timestamp.desc()
    ).limit(10).all()

    return render_template(
        'dashboard.html',
        files=files,
        total_used_bytes=total_used_bytes,
        storage_limit_bytes=storage_limit_bytes,
        used_percentage=round(used_percentage, 1),
        search_query=search_query,

        # Predictions Analytics
        total_predictions=total_predictions,
        average_confidence=avg_confidence,
        recent_predictions=recent_predictions,
        prediction_distribution=prediction_distribution,

        # Activity Log Summary
        timeline=timeline_logs,
        detection_name=current_app.config['DETECTION_NAME'],
        input_type=current_app.config['INPUT_TYPE']
    )

@main_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash("No file part selected.", "warning")
        return redirect(url_for('main.dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash("No file selected for upload.", "warning")
        return redirect(url_for('main.dashboard'))

    # Check limit check
    total_used = sum(f.file_size for f in File.query.filter_by(user_id=g.user.id, is_deleted=False).all())
    storage_limit = 100 * 1024 * 1024  # 100MB

    file.seek(0, 2)
    incoming_size = file.tell()
    file.seek(0)

    if total_used + incoming_size > storage_limit:
        flash("Upload rejected: You have exceeded your 100MB storage quota.", "danger")
        return redirect(url_for('main.dashboard'))

    try:
        orig_filename, disk_filename, file_size, mime_type = save_file_to_disk(file)

        file_record = File(
            user_id=g.user.id,
            filename=orig_filename,
            secure_filename=disk_filename,
            file_size=file_size,
            mime_type=mime_type
        )
        db.session.add(file_record)

        # Log to Database
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        log = ActivityLog(
            user_id=g.user.id,
            username=g.user.username,
            action='file_upload',
            ip_address=ip or 'Unknown',
            details=f"Uploaded file: '{orig_filename}'."
        )
        db.session.add(log)
        db.session.commit()

        flash(f"File '{orig_filename}' uploaded successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"File upload failed: {str(e)}", "danger")

    return redirect(url_for('main.dashboard'))

@main_bp.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)

    if file_record.user_id != g.user.id and g.user.role != 'admin':
        abort(403, description="Unauthorized file access request.")

    if file_record.is_deleted:
        abort(404, description="File has been deleted.")

    file_path = get_disk_file_path(file_record.secure_filename)
    if not file_path or not os.path.exists(file_path):
        flash("Physical file could not be found on disk storage.", "danger")
        return redirect(url_for('main.dashboard'))

    # Log audit event
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    db.session.add(ActivityLog(
        user_id=g.user.id,
        username=g.user.username,
        action='file_download',
        ip_address=ip or 'Unknown',
        details=f"Downloaded file: '{file_record.filename}'."
    ))
    db.session.commit()

    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_record.filename,
        mimetype=file_record.mime_type
    )

@main_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_record = File.query.get_or_404(file_id)

    if file_record.user_id != g.user.id and g.user.role != 'admin':
        abort(403, description="Unauthorized file deletion request.")

    file_record.is_deleted = True

    try:
        delete_file_from_disk(file_record.secure_filename)

        # Log audit event
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        db.session.add(ActivityLog(
            user_id=g.user.id,
            username=g.user.username,
            action='file_delete',
            ip_address=ip or 'Unknown',
            details=f"Deleted file: '{file_record.filename}'."
        ))
        db.session.commit()

        flash(f"File '{file_record.filename}' deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to delete file: {e}", "danger")

    return redirect(url_for('main.dashboard'))

@main_bp.route('/logs')
@login_required
def logs():
    user_logs = ActivityLog.query.filter_by(user_id=g.user.id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template('logs.html', logs=user_logs)
