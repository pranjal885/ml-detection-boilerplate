import os
import json
import joblib
import logging
from flask import current_app
from app.services.adapters import (
    TabularClassificationAdapter,
    TextClassificationAdapter,
    ImageClassificationAdapter,
    ObjectDetectionAdapter
)

logger = logging.getLogger(__name__)

# Global model cache to avoid loading from disk repeatedly
_model_cache = {}

def get_model():
    """Loads the ML model binary and caches it in memory."""
    model_path = current_app.config['MODEL_PATH']
    if model_path in _model_cache:
        return _model_cache[model_path]

    if not os.path.exists(model_path):
        logger.error(f"Active model binary not found at: {model_path}")
        return None

    try:
        model = joblib.load(model_path)
        _model_cache[model_path] = model
        logger.info(f"Loaded and cached model successfully from {model_path}")
        return model
    except Exception as e:
        logger.exception(f"Failed to load model from {model_path}: {e}")
        return None

def clear_model_cache():
    """Clears the cached model binary to support hot-swapping models."""
    global _model_cache
    _model_cache.clear()
    logger.info("Cleared cached model binaries.")

def get_model_metadata():
    """Loads metadata configuration parameters from models/config.json if available."""
    model_path = current_app.config['MODEL_PATH']
    model_dir = os.path.dirname(model_path)
    config_path = os.path.join(model_dir, 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading model config.json: {e}")

    # Test runner backup path support
    model_name = os.path.basename(model_path)
    backup_path = None
    if 'tabular_model' in model_name:
        backup_path = os.path.join(model_dir, 'tabular_config.json')
    elif 'text_model' in model_name:
        backup_path = os.path.join(model_dir, 'text_config.json')
    elif 'image_model' in model_name:
        backup_path = os.path.join(model_dir, 'image_config.json')
    elif 'object_detection_model' in model_name:
        backup_path = os.path.join(model_dir, 'object_detection_config.json')

    if backup_path and os.path.exists(backup_path):
        try:
            with open(backup_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass

    return {}

def get_adapter():
    """Resolves and instantiates the configured adapter."""
    adapter_name = current_app.config['MODEL_ADAPTER']
    model_name = current_app.config['DETECTION_NAME']
    model_version = current_app.config['MODEL_VERSION']

    adapters = {
        'TabularClassificationAdapter': TabularClassificationAdapter,
        'TextClassificationAdapter': TextClassificationAdapter,
        'ImageClassificationAdapter': ImageClassificationAdapter,
        'ObjectDetectionAdapter': ObjectDetectionAdapter
    }

    adapter_class = adapters.get(adapter_name)
    if adapter_class is None:
        # Fallback to dynamic lookup in adapters module
        import app.services.adapters as custom_adapters
        adapter_class = getattr(custom_adapters, adapter_name, None)

    if adapter_class is None:
        raise ValueError(f"Model adapter class not found: {adapter_name}")

    return adapter_class(model_name, model_version)

def run_inference(raw_input):
    """
    Executes the complete machine learning prediction pipeline.

    Args:
        raw_input: Raw data format suited for the adapter (e.g. image path, text string, feature dict).

    Returns:
        PredictionResult: Standardized prediction outcome.
    """
    model = get_model()
    if model is None:
        raise RuntimeError("Prediction failed: Active model binary could not be retrieved.")

    adapter = get_adapter()

    # Preprocess
    preprocessed_input = adapter.preprocess(raw_input)

    # Inference
    prediction_output = adapter.predict(model, preprocessed_input)

    # Postprocess
    result = adapter.postprocess(prediction_output)

    return result
