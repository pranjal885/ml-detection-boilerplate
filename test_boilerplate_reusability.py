import os
import json
import unittest
import numpy as np
import joblib
from flask import session
from sklearn.tree import DecisionTreeClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.pipeline import Pipeline

# Set environment variable to suppress warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

from app import create_app
from app.models import db, User, Prediction, ActivityLog
from app.services.inference import clear_model_cache

class MockImageClassifier:
    def predict(self, X):
        return ['Tomato Early Blight']
    def predict_proba(self, X):
        return np.array([[0.05, 0.95]])

class MockObjectDetector:
    def detect(self, X):
        return [{"box_2d": [10, 20, 100, 200], "label": "Person", "score": 0.91}]

class MockObjectDetector2:
    def detect(self, X):
        return [{"box_2d": [5, 10, 50, 100], "label": "Car", "score": 0.85}]

class TestBoilerplateReusability(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create models directory if not exists
        os.makedirs('models', exist_ok=True)

        # 1. Train and save Model A: Tabular Classifier
        X_tab = np.array([[1.0, 2.0, 3.0], [10.0, 20.0, 30.0]])
        y_tab = np.array(['Safe', 'Unsafe'])
        clf_tab = DecisionTreeClassifier()
        clf_tab.fit(X_tab, y_tab)
        joblib.dump(clf_tab, 'models/tabular_model.pkl')

        # Write Model A config metadata
        tabular_metadata = {
            "features": [
                {"name": "feature_1", "type": "number", "default": 1.0},
                {"name": "feature_2", "type": "number", "default": 2.0},
                {"name": "feature_3", "type": "number", "default": 3.0}
            ]
        }
        with open('models/tabular_config.json', 'w') as f:
            json.dump(tabular_metadata, f)

        # 1.2. Train and save Model A2: Tabular Classifier (predicts Unsafe for Safe input)
        X_tab_2 = np.array([[1.0, 2.0, 3.0], [10.0, 20.0, 30.0]])
        y_tab_2 = np.array(['Unsafe', 'Safe'])
        clf_tab_2 = DecisionTreeClassifier()
        clf_tab_2.fit(X_tab_2, y_tab_2)
        joblib.dump(clf_tab_2, 'models/tabular_model_2.pkl')

        # Write Model A2 config metadata
        tabular_metadata_2 = {
            "features": [
                {"name": "feature_1", "type": "number", "default": 1.0},
                {"name": "feature_2", "type": "number", "default": 2.0},
                {"name": "feature_3", "type": "number", "default": 3.0}
            ]
        }
        with open('models/tabular_config_2.json', 'w') as f:
            json.dump(tabular_metadata_2, f)

        # 2. Train and save Model B: Text Vectorizer + Classifier Pipeline
        corpus = ["Good text pattern", "Bad text pattern"]
        labels = ["Positive", "Negative"]
        pipeline = Pipeline([
            ('vectorizer', CountVectorizer()),
            ('classifier', DecisionTreeClassifier())
        ])
        pipeline.fit(corpus, labels)
        joblib.dump(pipeline, 'models/text_model.pkl')

        # Write Model B config metadata
        text_metadata = {
            "features": []
        }
        with open('models/text_config.json', 'w') as f:
            json.dump(text_metadata, f)

        # 3. Dump Model C: Image Classifier
        image_clf = MockImageClassifier()
        joblib.dump(image_clf, 'models/image_model.pkl')
        with open('models/image_config.json', 'w') as f:
            json.dump({"features": []}, f)

        # 4. Dump Model D1: Object Detector
        detector_1 = MockObjectDetector()
        joblib.dump(detector_1, 'models/object_detection_model.pkl')
        with open('models/object_detection_config.json', 'w') as f:
            json.dump({"features": []}, f)

        # 5. Dump Model D2: Alternative Object Detector (for hot-swapping test)
        detector_2 = MockObjectDetector2()
        joblib.dump(detector_2, 'models/object_detection_model_2.pkl')

    def setUp(self):
        # Instantiate test app
        self.app = create_app()
        self.app.config['TESTING'] = True

        # Setup SQLite Database context
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['UPLOAD_FOLDER'] = os.path.abspath('test_uploads')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        db.create_all()

        # Seed test user
        self.username = "scientist"
        self.email = "scientist@boilerplate.org"
        self.password = "securepass123"

        user = User(username=self.username, email=self.email, role='user')
        user.set_password(self.password)
        db.session.add(user)
        db.session.commit()
        self.user_id = user.id

        # Authenticate User session
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.user_id
            sess['role'] = 'user'

    def tearDown(self):
        clear_model_cache()
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

        # Cleanup uploaded test files
        if os.path.exists('test_uploads'):
            import shutil
            shutil.rmtree('test_uploads')

    @classmethod
    def tearDownClass(cls):
        # Cleanup mock artifacts from disk
        for file in ['models/tabular_model.pkl', 'models/tabular_config.json',
                     'models/tabular_model_2.pkl', 'models/tabular_config_2.json',
                     'models/text_model.pkl', 'models/text_config.json',
                     'models/image_model.pkl', 'models/image_config.json',
                     'models/object_detection_model.pkl', 'models/object_detection_model_2.pkl',
                     'models/object_detection_config.json']:
            if os.path.exists(file):
                os.remove(file)

    def test_run_with_model_a_tabular(self):
        """Test Case: Configure and run tabular Model A prediction, checking database commits and dashboard metrics."""
        # Configure app settings for Model A
        self.app.config['DETECTION_NAME'] = "Tabular Risk Classifier"
        self.app.config['MODEL_TYPE'] = "tabular"
        self.app.config['MODEL_PATH'] = os.path.abspath('models/tabular_model.pkl')
        self.app.config['MODEL_ADAPTER'] = "TabularClassificationAdapter"
        self.app.config['INPUT_TYPE'] = "tabular"

        # 1. Verify GET predict form renders correctly
        resp_get = self.client.get('/prediction/predict')
        self.assertEqual(resp_get.status_code, 200)
        self.assertIn(b"Tabular Risk Classifier", resp_get.data)
        self.assertIn(b"feature_1", resp_get.data)

        # 2. POST prediction input data
        post_data = {
            'feature_1': '1.2',
            'feature_2': '2.2',
            'feature_3': '3.2'
        }
        resp_post = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)

        # Verify db persistence
        pred = Prediction.query.filter_by(user_id=self.user_id).first()
        self.assertIsNotNone(pred)
        self.assertEqual(pred.input_type, 'tabular')
        self.assertEqual(pred.prediction_class, 'Safe')
        self.assertEqual(pred.model_name, "Tabular Risk Classifier")

        # Verify audit log is saved
        audit = ActivityLog.query.filter_by(action='predict').first()
        self.assertIsNotNone(audit)
        self.assertIn("Label=Safe", audit.details)

        # 3. Verify dashboard statistics render correctly
        resp_dash = self.client.get('/dashboard')
        self.assertEqual(resp_dash.status_code, 200)
        self.assertIn(b"Tabular Risk Classifier Dashboard", resp_dash.data)
        self.assertIn(b"TOTAL INFERENCES", resp_dash.data)
        self.assertIn(b"Safe", resp_dash.data)

    def test_run_with_model_b_text(self):
        """Test Case: Configure and run text Model B prediction, checking database commits and dashboard metrics."""
        # Configure app settings for Model B
        self.app.config['DETECTION_NAME'] = "Text Sentiment Classifier"
        self.app.config['MODEL_TYPE'] = "text"
        self.app.config['MODEL_PATH'] = os.path.abspath('models/text_model.pkl')
        self.app.config['MODEL_ADAPTER'] = "TextClassificationAdapter"
        self.app.config['INPUT_TYPE'] = "text"

        # 1. Verify GET predict form renders correctly
        resp_get = self.client.get('/prediction/predict')
        self.assertEqual(resp_get.status_code, 200)
        self.assertIn(b"Text Sentiment Classifier", resp_get.data)

        # 2. POST prediction input text
        post_data = {
            'text': 'Good text pattern'
        }
        resp_post = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)

        # Verify db persistence
        pred = Prediction.query.filter_by(user_id=self.user_id).first()
        self.assertIsNotNone(pred)
        self.assertEqual(pred.input_type, 'text')
        self.assertEqual(pred.prediction_class, 'Positive')
        self.assertEqual(pred.model_name, "Text Sentiment Classifier")

        # Verify dashboard statistics render correctly
        resp_dash = self.client.get('/dashboard')
        self.assertEqual(resp_dash.status_code, 200)
        self.assertIn(b"Text Sentiment Classifier Dashboard", resp_dash.data)
        self.assertIn(b"Positive", resp_dash.data)

    def test_run_with_model_c_image(self):
        """Test Case: Configure and run image classification Model C prediction, checking database commits and dashboard metrics."""
        self.app.config['DETECTION_NAME'] = "Tomato Disease Classifier"
        self.app.config['MODEL_TYPE'] = "image"
        self.app.config['MODEL_PATH'] = os.path.abspath('models/image_model.pkl')
        self.app.config['MODEL_ADAPTER'] = "ImageClassificationAdapter"
        self.app.config['INPUT_TYPE'] = "image"
        self.app.config['MODEL_VERSION'] = "1.0.0"

        # 1. Verify GET predict form renders correctly
        resp_get = self.client.get('/prediction/predict')
        self.assertEqual(resp_get.status_code, 200)
        self.assertIn(b"Tomato Disease Classifier", resp_get.data)

        # 2. POST prediction with mock image file upload
        import io
        post_data = {
            'file': (io.BytesIO(b"fake image data"), 'tomato_early_blight.jpg')
        }
        resp_post = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)

        # Verify db persistence
        pred = Prediction.query.filter_by(user_id=self.user_id).first()
        self.assertIsNotNone(pred)
        self.assertEqual(pred.input_type, 'image')
        self.assertEqual(pred.prediction_class, 'Tomato Early Blight')
        self.assertEqual(pred.model_name, "Tomato Disease Classifier")

        # Verify dashboard statistics render correctly
        resp_dash = self.client.get('/dashboard')
        self.assertEqual(resp_dash.status_code, 200)
        self.assertIn(b"Tomato Disease Classifier Dashboard", resp_dash.data)

    def test_run_with_model_d_object_detection(self):
        """Test Case: Configure and run object detection Model D prediction, verifying bounding boxes are saved and rendered."""
        self.app.config['DETECTION_NAME'] = "Object Detection Model"
        self.app.config['MODEL_TYPE'] = "object_detection"
        self.app.config['MODEL_PATH'] = os.path.abspath('models/object_detection_model.pkl')
        self.app.config['MODEL_ADAPTER'] = "ObjectDetectionAdapter"
        self.app.config['INPUT_TYPE'] = "object_detection"
        self.app.config['MODEL_VERSION'] = "2.1.0"

        # 1. Verify GET predict form renders correctly
        resp_get = self.client.get('/prediction/predict')
        self.assertEqual(resp_get.status_code, 200)
        self.assertIn(b"Object Detection Model", resp_get.data)

        # 2. POST prediction with mock image file upload
        import io
        post_data = {
            'file': (io.BytesIO(b"fake image data"), 'street_scene.jpg')
        }
        resp_post = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)

        # Verify db persistence
        pred = Prediction.query.filter_by(user_id=self.user_id).first()
        self.assertIsNotNone(pred)
        self.assertEqual(pred.input_type, 'object_detection')
        self.assertEqual(pred.prediction_class, 'Person')
        self.assertEqual(pred.model_name, "Object Detection Model")

        # Verify metadata contains bounding box coordinates
        meta = json.loads(pred.metadata_json)
        self.assertIn('bounding_box', meta)
        self.assertEqual(meta['bounding_box'], [10, 20, 100, 200])

        # Verify dashboard statistics render correctly
        resp_dash = self.client.get('/dashboard')
        self.assertEqual(resp_dash.status_code, 200)
        self.assertIn(b"Object Detection Model Dashboard", resp_dash.data)

    def test_model_hot_swapping_reusability(self):
        """Test Case: Demonstrate hot-swapping compatible models via config without changing any core application code."""
        # 1. First run with detector_1 (Object Detector 1)
        self.app.config['DETECTION_NAME'] = "Generic Object Detector"
        self.app.config['MODEL_TYPE'] = "object_detection"
        self.app.config['MODEL_PATH'] = os.path.abspath('models/object_detection_model.pkl')
        self.app.config['MODEL_ADAPTER'] = "ObjectDetectionAdapter"
        self.app.config['INPUT_TYPE'] = "object_detection"
        self.app.config['MODEL_VERSION'] = "1.0.0"

        import io
        post_data = {
            'file': (io.BytesIO(b"fake image data"), 'street.jpg')
        }
        resp = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        pred_1 = Prediction.query.order_by(Prediction.id.desc()).first()
        self.assertEqual(pred_1.prediction_class, 'Person')
        self.assertEqual(pred_1.confidence, 91.0)
        meta_1 = json.loads(pred_1.metadata_json)
        self.assertEqual(meta_1['bounding_box'], [10, 20, 100, 200])

        # 2. Hot-swap active model to detector_2 (Object Detector 2)
        # Simply change config values & clear the model cache, simulating a config update or environment variable swap
        clear_model_cache()
        self.app.config['MODEL_PATH'] = os.path.abspath('models/object_detection_model_2.pkl')
        self.app.config['MODEL_VERSION'] = "2.0.0"

        # POST the same input image data without modifying any core application code
        post_data_swap = {
            'file': (io.BytesIO(b"fake image data"), 'street.jpg')
        }
        resp_swap = self.client.post('/prediction/predict', data=post_data_swap, follow_redirects=True)
        self.assertEqual(resp_swap.status_code, 200)

        pred_2 = Prediction.query.order_by(Prediction.id.desc()).first()
        self.assertEqual(pred_2.prediction_class, 'Car')
        self.assertEqual(pred_2.confidence, 85.0)
        meta_2 = json.loads(pred_2.metadata_json)
        self.assertEqual(meta_2['bounding_box'], [5, 10, 50, 100])

        # Verify both predictions are saved and correct, demonstrating successful model replacement via configurations
        self.assertNotEqual(pred_1.id, pred_2.id)

    def test_tabular_model_hot_swapping_reusability(self):
        """Test Case: Demonstrate hot-swapping compatible tabular models via config without changing any core application code."""
        # 1. First run with tabular Model A
        self.app.config['DETECTION_NAME'] = "Tabular Risk Classifier"
        self.app.config['MODEL_TYPE'] = "tabular"
        self.app.config['MODEL_PATH'] = os.path.abspath('models/tabular_model.pkl')
        self.app.config['MODEL_ADAPTER'] = "TabularClassificationAdapter"
        self.app.config['INPUT_TYPE'] = "tabular"
        self.app.config['MODEL_VERSION'] = "1.0.0"

        post_data = {
            'feature_1': '1.2',
            'feature_2': '2.2',
            'feature_3': '3.2'
        }
        resp_1 = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp_1.status_code, 200)

        pred_1 = Prediction.query.order_by(Prediction.id.desc()).first()
        self.assertIsNotNone(pred_1)
        self.assertEqual(pred_1.prediction_class, 'Safe')

        # 2. Hot-swap active model to tabular Model A2
        # Simply change config values & clear the model cache, simulating a config update or environment variable swap
        clear_model_cache()
        self.app.config['MODEL_PATH'] = os.path.abspath('models/tabular_model_2.pkl')
        self.app.config['MODEL_VERSION'] = "2.0.0"

        # POST the same input data without modifying any core application code
        resp_2 = self.client.post('/prediction/predict', data=post_data, follow_redirects=True)
        self.assertEqual(resp_2.status_code, 200)

        pred_2 = Prediction.query.order_by(Prediction.id.desc()).first()
        self.assertIsNotNone(pred_2)
        self.assertEqual(pred_2.prediction_class, 'Unsafe')

        # Verify both predictions are saved and correct, demonstrating successful model replacement via configurations
        self.assertNotEqual(pred_1.id, pred_2.id)

if __name__ == '__main__':
    unittest.main()
