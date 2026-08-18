import logging
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

class PredictionResult:
    """Standardized prediction output representation."""
    def __init__(self, label, confidence, model_name, model_version, metadata=None):
        self.label = label
        conf = float(confidence)
        # Standardize fractional confidence (0.0 to 1.0) to percentage (0.0 to 100.0)
        # to ensure database statistics and UI rendering work correctly.
        if 0.0 < conf <= 1.0:
            self.confidence = conf * 100.0
        else:
            self.confidence = conf
        self.model_name = model_name
        self.model_version = model_version
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            'label': self.label,
            'confidence': self.confidence,
            'model_name': self.model_name,
            'model_version': self.model_version,
            'metadata': self.metadata
        }

class BaseModelAdapter:
    """Abstract base class establishing the model prediction contract."""
    def __init__(self, model_name, model_version):
        self.model_name = model_name
        self.model_version = model_version

    def preprocess(self, raw_input):
        """Transform raw input into features appropriate for the estimator."""
        raise NotImplementedError("Subclasses must implement preprocess.")

    def predict(self, model, preprocessed_input):
        """Run the actual machine learning prediction method."""
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(preprocessed_input)
            pred = model.predict(preprocessed_input)
            return pred, probs
        elif hasattr(model, 'predict'):
            return model.predict(preprocessed_input), None
        else:
            raise AttributeError("Provided model does not support predict or predict_proba.")

    def postprocess(self, prediction_output):
        """Parse raw prediction outcomes into a standard PredictionResult instance."""
        raise NotImplementedError("Subclasses must implement postprocess.")


class TabularClassificationAdapter(BaseModelAdapter):
    """Adapter for numerical and categorical tabular classification models."""
    def preprocess(self, raw_input):
        # raw_input is a dictionary of features
        if isinstance(raw_input, pd.DataFrame):
            return raw_input
        if isinstance(raw_input, dict):
            return pd.DataFrame([raw_input])
        return pd.DataFrame(raw_input)

    def postprocess(self, prediction_output):
        pred, probs = prediction_output
        label = str(pred[0])
        confidence = 100.0
        if probs is not None:
            confidence = float(np.max(probs[0]) * 100.0)
        return PredictionResult(label, confidence, self.model_name, self.model_version)


class TextClassificationAdapter(BaseModelAdapter):
    """Adapter for natural language processing text classification models."""
    def preprocess(self, raw_input):
        # raw_input is a text string
        if isinstance(raw_input, str):
            return [raw_input]
        return raw_input

    def postprocess(self, prediction_output):
        pred, probs = prediction_output
        label = str(pred[0])
        confidence = 100.0
        if probs is not None:
            confidence = float(np.max(probs[0]) * 100.0)
        return PredictionResult(label, confidence, self.model_name, self.model_version)


class ImageClassificationAdapter(BaseModelAdapter):
    """Adapter for computer vision image classification models."""
    def preprocess(self, raw_input):
        # raw_input is path to the saved image file
        return raw_input

    def postprocess(self, prediction_output):
        pred, probs = prediction_output
        label = str(pred[0])
        confidence = 100.0
        if probs is not None:
            confidence = float(np.max(probs[0]) * 100.0)
        return PredictionResult(label, confidence, self.model_name, self.model_version)


class ObjectDetectionAdapter(BaseModelAdapter):
    """Adapter for computer vision object detection models returning bounding boxes."""
    def preprocess(self, raw_input):
        # raw_input is path to the saved image file
        return raw_input

    def predict(self, model, preprocessed_input):
        if hasattr(model, 'detect'):
            return model.detect(preprocessed_input)
        elif hasattr(model, 'predict'):
            return model.predict(preprocessed_input)
        else:
            raise AttributeError("Provided model does not support predict or detect.")

    def postprocess(self, prediction_output):
        # prediction_output can be list of dicts: [{"box_2d": [ymin, xmin, ymax, xmax], "label": "X", "score": 0.9}]
        detections = []
        label = "No Detections"
        max_score = 0.0

        if isinstance(prediction_output, list):
            detections = prediction_output
            if len(detections) > 0:
                best_det = max(detections, key=lambda x: x.get('score', 0.0))
                label = best_det.get('label', 'Object')
                max_score = best_det.get('score', 0.0)
        elif isinstance(prediction_output, dict):
            label = prediction_output.get('label', 'Object')
            max_score = prediction_output.get('score', 0.0)
            detections = prediction_output.get('detections', [prediction_output])
        else:
            label = str(prediction_output)
            max_score = 1.0
            detections = [{"label": label, "score": 1.0}]

        metadata = {'detections': detections}
        if len(detections) > 0:
            best_det = max(detections, key=lambda x: x.get('score', 0.0))
            box = best_det.get('bounding_box') or best_det.get('box_2d')
            if box:
                metadata['bounding_box'] = box

        return PredictionResult(label, max_score, self.model_name, self.model_version, metadata=metadata)
