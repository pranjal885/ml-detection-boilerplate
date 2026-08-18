import os
import json
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, jsonify, current_app, send_from_directory
from app.models import db, Prediction, ActivityLog
from app.routes.auth import login_required
from app.services.storage import save_file_to_disk, get_disk_file_path
from app.services.inference import run_inference, get_model_metadata

logger = logging.getLogger(__name__)
prediction_bp = Blueprint('prediction', __name__, url_prefix='/prediction')

@prediction_bp.route('/uploads/<filename>')
@login_required
def serve_upload(filename):
    """Serves uploaded input media for user display."""
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@prediction_bp.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    """Handles prediction input rendering and submissions."""
    input_type = current_app.config['INPUT_TYPE']
    detection_name = current_app.config['DETECTION_NAME']
    metadata = get_model_metadata()
    features = metadata.get('features', [])

    if request.method == 'GET':
        return render_template(
            'prediction/input.html',
            detection_name=detection_name,
            input_type=input_type,
            features=features
        )

    # POST processing
    raw_input = None
    input_display_value = ""

    try:
        if input_type in ['image', 'object_detection'] or current_app.config['MODEL_TYPE'] == 'object_detection':
            if 'file' not in request.files:
                flash("No file part provided.", "warning")
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash("No file selected.", "warning")
                return redirect(request.url)

            orig_filename, disk_filename, file_size, mime_type = save_file_to_disk(file)
            raw_input = get_disk_file_path(disk_filename)
            input_display_value = disk_filename # Save disk name for image tags

        elif input_type == 'text':
            text_data = request.form.get('text', '').strip()
            if not text_data:
                flash("Text input cannot be empty.", "warning")
                return redirect(request.url)
            raw_input = text_data
            input_display_value = text_data

        elif input_type == 'tabular':
            tabular_data = {}
            for f in features:
                val = request.form.get(f['name'], '').strip()
                if val == '' and 'default' in f:
                    val = f['default']

                # Convert type
                if f.get('type') == 'number':
                    try:
                        val = float(val) if '.' in str(val) else int(val)
                    except ValueError:
                        val = 0.0
                tabular_data[f['name']] = val

            raw_input = tabular_data
            input_display_value = json.dumps(tabular_data)

        else:
            raise ValueError(f"Invalid input type: {input_type}")

        # Run inference
        result = run_inference(raw_input)

        # Save to Database
        prediction_record = Prediction(
            user_id=g.user.id,
            input_type=input_type,
            input_data=input_display_value,
            prediction_class=result.label,
            confidence=result.confidence,
            model_name=result.model_name,
            model_version=result.model_version,
            metadata_json=json.dumps(result.metadata)
        )
        db.session.add(prediction_record)
        db.session.commit()

        # Audit log
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        db.session.add(ActivityLog(
            user_id=g.user.id,
            username=g.user.username,
            action='predict',
            ip_address=ip or 'Unknown',
            details=f"Inference execution. Label={result.label}, Confidence={result.confidence:.1f}%"
        ))
        db.session.commit()

        # Check for JSON request
        if request.headers.get('Accept') == 'application/json' or request.is_json:
            return jsonify({
                'id': prediction_record.id,
                'result': result.to_dict()
            })

        return redirect(url_for('prediction.result', prediction_id=prediction_record.id))

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Prediction execution failed: {e}")
        flash(f"Prediction failed: {str(e)}", "danger")
        return redirect(request.url)


@prediction_bp.route('/result/<int:prediction_id>')
@login_required
def result(prediction_id):
    """Displays detailed metrics of a specific prediction."""
    prediction = Prediction.query.get_or_404(prediction_id)

    # Restrict views to owner or admin
    if prediction.user_id != g.user.id and g.user.role != 'admin':
        flash("Unauthorized access attempt.", "danger")
        return redirect(url_for('main.dashboard'))

    # Parse metadata json
    meta = {}
    if prediction.metadata_json:
        try:
            meta = json.loads(prediction.metadata_json)
        except Exception:
            pass

    return render_template(
        'prediction/result.html',
        prediction=prediction,
        metadata=meta,
        detection_name=current_app.config['DETECTION_NAME']
    )
