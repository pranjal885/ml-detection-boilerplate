# ML Detection Boilerplate

## 1. Overview
The **ML Detection Boilerplate** is a highly reusable, generic Machine Learning (ML) web application boilerplate designed to decouple core application features from the underlying machine learning models.

Often, ML web interfaces require implementing the same repeated platform layers: authentication, registration, database persistence, audit logging, dashboard metrics, and a prediction user interface. Under the **"same application, different model"** paradigm, this project provides a unified architecture. By standardizing input ingestion and prediction formatting, developers can swap or upgrade model binaries (e.g., transitioning from emotion detection to fruit classification, tomato disease identification, or generic object detection) simply by altering environment variables and configuration files, with zero changes to the core application code.

---

## 2. Key Features
- **User Registration and Login**: Secure registration and session-based login with bcrypt password hashing and view-level authorization filters.
- **Admin Panel**: Dedicated administrator interface to audit system activity, view logs, and manage user access.
- **User Management**: Advanced administration control allowing administrators to block or unblock user accounts.
- **Dashboard**: A clean, metrics-driven analytics dashboard displaying aggregate inference metrics, prediction class distributions, and history.
- **Prediction History and Logs**: Persistent audit trails storing prediction classes, confidence scores, model names, versions, features, and model-specific metadata.
- **Generic ML Inference Service**: A centralized service layer (`app/services/inference.py`) that manages model caching, resolves adapters, and executes inference pipelines.
- **Multiple Model Types**: Out-of-the-box support for tabular classification, text classification, image classification, and object detection.
- **Object Detection with Bounding Boxes**: Dynamic rendering of detection boxes and label overlays on uploaded images directly inside the browser using HTML5 Canvas.
- **Configuration-Driven Model Swapping**: Swap model binaries and configuration files by changing environment variables, with the option to clear the global model cache using `clear_model_cache()` during a running process.
- **Standardized PredictionResult**: A unified internal data contract representing prediction outcomes to ensure database schemas and dashboards remain invariant.
- **Automated Reusability Tests**: A regression testing suite containing 6 automated reusability tests validating model swapping and pipeline compatibility.

---

## 3. Supported Model Types
The boilerplate utilizes specialized adapters (inheriting from `BaseModelAdapter` in `app/services/adapters.py`) to interface with different categories of machine learning algorithms:

*   **`TabularClassificationAdapter`**: Integrates classification models operating on structured rows. Transforms incoming form variables into a pandas DataFrame and queries prediction probabilities.
*   **`TextClassificationAdapter`**: Interfaces with NLP text classification systems. Passes raw strings or list objects to pipelines (e.g. Scikit-learn pipelines containing vectorizers).
*   **`ImageClassificationAdapter`**: Wraps standard image classifiers by passing the saved file path of the uploaded image to the model's prediction method.
*   **`ObjectDetectionAdapter`**: Standardizes computer vision object detection systems. Extracts label categories, scores, and 2D bounding boxes (e.g., `[ymin, xmin, ymax, xmax]`), storing them in a standardized metadata block.

---

## 4. System Architecture
The application is structured in decoupled layers, ensuring a unidirectional data flow and clean separation of concerns:

```
User Interface (HTML/CSS/JS)
       ↓
Flask Routes (Blueprints)
       ↓
Inference Service (inference.py)
       ↓
Model Adapter (adapters.py)
       ↓
ML Model (pkl binary)
       ↓
PredictionResult (Standard Output)
       ↓
Database / Dashboard / Logs (Persistence & Analytics)
```

### Layer Responsibilities
- **User Interface**: Handles web views, user input collection (via forms or file uploads), and dynamic JavaScript rendering (e.g. canvas overlays for bounding boxes).
- **Flask Routes**: Manages HTTP requests/responses, session validations, files upload validation, database queries, and passes the payload to the services layer.
- **Inference Service**: Handles model loading, caches model instances in memory for performance, resolves the configured adapter class, and runs the inference orchestrator.
- **Model Adapter**: Resolves the differences between models. Preprocesses HTTP inputs, queries the model binary, and converts raw output structures into a standard result.
- **ML Model**: Serialized binary containing the model parameters and weights (e.g., joblib/pickle pkl).
- **PredictionResult**: The standard internal contract representing prediction outcomes.
- **Database / Dashboard / Logs**: Persists outputs to the `predictions` table, updates telemetry logs, and aggregates stats for dashboard visualization.

---

## 5. Generic Prediction Pipeline
The application routes all inference requests through a strict pipeline inside `app/services/inference.py`:

```
raw input ──> preprocess() ──> predict() ──> postprocess() ──> PredictionResult ──> persistence/display
```

1.  **Raw Input**: Input data received from web forms or uploaded files.
2.  `preprocess()`: The active adapter formats the raw input (e.g. text string, feature dictionary, image path) into features suitable for the model (e.g., NumPy array or pandas DataFrame).
3.  `predict()`: The adapter invokes the cached model's primary prediction APIs (e.g., checks for `predict_proba()`, `predict()`, or custom `detect()`).
4.  `postprocess()`: Raw model outputs are standardized. If probabilities are available, confidence is calculated and scaled to a percentage range (0.0% to 100.0%).
5.  `PredictionResult`: A standardized result is created.
6.  **Persistence/Display**: The system writes records to the database and sends the JSON representation to the client for rendering.

---

## 6. PredictionResult
Every adapter must return a standardized `PredictionResult` object. This guarantees that Flask routes and SQLAlchemy models do not need modifications when swapping models.

### Class Attributes
- **`label`** *(str)*: The predicted class name or primary category.
- **`confidence`** *(float)*: Prediction confidence score represented as a percentage (0.0 to 100.0).
- **`model_name`** *(str)*: Name of the active model that evaluated the input.
- **`model_version`** *(str)*: Semantic version of the active model.
- **`metadata`** *(dict)*: Dictionary of custom attributes.

For **object detection models**, the adapter includes a list of detections inside the `metadata` dictionary:
- `detections`: A list of detection dictionaries, each containing:
  - `box_2d`: Coordinates of the bounding box (`[ymin, xmin, ymax, xmax]`).
  - `label`: Label of the detected object.
  - `score`: Model confidence score for the object.
- `bounding_box`: The box coordinate array `[ymin, xmin, ymax, xmax]` of the highest-scoring detection, which the frontend uses to display highlights.

---

## 7. Adapter Architecture
The application uses the Adapter Pattern to wrap ML libraries under a common interface. The base class is defined as follows:

```python
class BaseModelAdapter:
    def __init__(self, model_name, model_version):
        self.model_name = model_name
        self.model_version = model_version

    def preprocess(self, raw_input):
        raise NotImplementedError("Subclasses must implement preprocess.")

    def predict(self, model, preprocessed_input):
        # Default behavior checks for predict_proba or predict
        if hasattr(model, 'predict_proba'):
            probs = model.predict_proba(preprocessed_input)
            pred = model.predict(preprocessed_input)
            return pred, probs
        elif hasattr(model, 'predict'):
            return model.predict(preprocessed_input), None
        raise AttributeError("Provided model does not support predict or predict_proba.")

    def postprocess(self, prediction_output):
        raise NotImplementedError("Subclasses must implement postprocess.")
```

### Why This Enables Reusability
Because the Flask views only invoke `run_inference(raw_input)`, the application is decoupled from all machine learning libraries. Whether the model is built with scikit-learn, TensorFlow, PyTorch, or OpenCV, the complexity is encapsulated in the adapter class. Modifying inputs/outputs only requires updating the adapter, while routes, database persistence, and general templates remain unchanged.

---

## 8. Object Detection
The boilerplate contains full support for object detection tasks via `ObjectDetectionAdapter`.

- **Prediction Method**: The adapter dynamically executes the model's `detect(X)` or `predict(X)` method.
- **Bounding Box Format**: Bounding boxes are formatted as a 4-element coordinate list `[ymin, xmin, ymax, xmax]` or passed via `box_2d` structures. The UI reads these coordinates to project canvas frames onto uploaded images.

### Example PredictionResult JSON:
```json
{
  "label": "Person",
  "confidence": 94.0,
  "model_name": "Generic Object Detection",
  "model_version": "1.0.0",
  "metadata": {
    "detections": [
      {
        "box_2d": [40, 50, 400, 600],
        "label": "Person",
        "score": 0.94
      }
    ],
    "bounding_box": [40, 50, 400, 600]
  }
}
```

---

## 9. Model Configuration
The application behavior is driven entirely by environment variables parsed in `app/config.py`:

| Variable Name | Description | Default / Fallback |
| :--- | :--- | :--- |
| `SECRET_KEY` | Flask session signature key | `'dev-only-secret-key-change-me'` |
| `DB_USER` | MySQL Username | `None` (triggers SQLite fallback) |
| `DB_PASSWORD` | MySQL Password | `None` |
| `DB_HOST` | MySQL Host | `'localhost'` |
| `DB_PORT` | MySQL Port | `'3306'` |
| `DB_NAME` | MySQL Database Name | `None` (triggers SQLite fallback) |
| `UPLOAD_FOLDER` | Destination folder for image uploads | `uploads/` |
| `DETECTION_NAME`| Human-readable name displayed on UI | `'Generic ML Detection'` |
| `MODEL_TYPE` | Type of prediction: `tabular`, `text`, `image`, `object_detection` | `'tabular'` |
| `MODEL_PATH` | Path to the serialized `.pkl` binary | `models/model.pkl` |
| `MODEL_VERSION` | Semantic version label | `'1.0.0'` |
| `MODEL_ADAPTER` | Python adapter class name | `'TabularClassificationAdapter'` |
| `INPUT_TYPE` | HTML form input type: `tabular`, `text`, `image` | `'tabular'` |

*Note: For local development, if `DB_USER` and `DB_NAME` are not supplied, the application automatically falls back to an SQLite database saved locally inside `instance/cloudvault.db`.*

---

## 10. Model Swapping
Model swapping in this boilerplate is configuration-driven and can be completed in four steps without editing the core application code. When changing models during a running process, the global model cache can be cleared using `clear_model_cache()` to load the new model binary:

1.  **Deploy Binary**: Save the new pickled model (e.g. `my_new_classifier.pkl`) in the `models/` directory.
2.  **Define Configuration (If Tabular)**: If swapping a tabular model, save a feature configuration (e.g. `config.json` inside the model's directory) specifying the expected field names, input types, and defaults.
3.  **Update Environment**: Modify the environment variables to bind the new model settings. For example, in PowerShell:
    ```powershell
    $env:MODEL_PATH="models/my_new_classifier.pkl"
    $env:MODEL_ADAPTER="ImageClassificationAdapter"
    $env:MODEL_TYPE="image"
    $env:INPUT_TYPE="image"
    $env:DETECTION_NAME="Fruit Classifier"
    $env:MODEL_VERSION="2.1.0"
    ```
4.  **Clear Model Cache**: Invoke `clear_model_cache()` to clear the globally cached model binary and allow the application to load the newly configured model on the next inference request.

### Swapping Scenarios Demonstrated in Reusability Tests:
- **Tabular Model A → Model A2**: Swapping the model binary updates predictions from "Safe" to "Unsafe" based on identical input features.
- **Object Detector V1 → V2**: Swapping the model configuration to point to V2 (using `models/object_detection_model_v2.pkl` and `models/object_detection_config_v2.json`) alters detection classes (e.g. from "Person" to "Dog"/"Car") and updates the drawn coordinates dynamically.

---

## 11. Mock Models
The repository includes mock ML model classes inside `app/services/mock_models.py` (and generated via `generate_mock_models.py`):
- `MockObjectDetector`
- `MockObjectDetectorV2`

These classes are included **exclusively** to demonstrate the data pipelines, test hot-swapping configurations, verify database structures, and confirm front-end canvas plotting. They are simple mock classes returning predefined coordinate arrays and labels, and are **not** production-grade ML models.

---

## 12. Project Structure
The main components of the repository are organized as follows:

```
ml-detection-boilerplate/
├── app/                             # Core Flask application package
│   ├── __init__.py                  # Application factory, session setup, database binding
│   ├── config.py                    # Environment variable parser and settings
│   ├── models.py                    # Database models (User, File, ActivityLog, Prediction)
│   ├── routes/                      # Flask blueprints for route handling
│   │   ├── admin.py                 # Admin dashboard, blocking controls, activity audit logs
│   │   ├── auth.py                  # Authentication endpoints (login, register, logout)
│   │   ├── main.py                  # Index, profile, and generic file uploads
│   │   └── prediction.py            # Model inference, predict UI forms, history endpoints
│   ├── services/                    # Business and ML helper services
│   │   ├── adapters.py              # BaseModelAdapter and model wrapper definitions
│   │   ├── events.py                # Telemetry event hooks
│   │   ├── inference.py             # Inference pipeline execution and model cache manager
│   │   ├── mock_models.py           # Mock object detection classes
│   │   ├── storage.py               # Uploaded file management
│   │   └── telemetry.py             # User activity audit logger
│   ├── static/                      # Static assets (CSS styles, JS files)
│   └── templates/                   # Jinja2 layout templates
│       └── prediction/
│           └── input.html           # Prediction input form and object detection Canvas drawer
├── models/                          # Directory for serialized ML model binaries
├── generate_mock_models.py          # Script generating mockup model binaries on disk
├── test_boilerplate_reusability.py  # Automation reusability test suite (6 tests)
├── requirements.txt                 # Application Python dependencies
├── run.py                           # Application startup entrypoint script
└── schema.sql                       # Database initialization schema (MySQL)
```

---

## 13. Installation
Follow these instructions using Windows PowerShell to clone and install the application locally:

```powershell
# 1. Clone the repository
git clone <repository-url>
cd ml-detection-boilerplate

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the virtual environment
.venv\Scripts\Activate.ps1

# 4. Install the required packages
pip install -r requirements.txt
```

---

## 14. Configuration and Running
To configure the environment for running the mock **object detection** pipeline locally, execute the following commands in Windows PowerShell:

```powershell
# 1. (Optional) Run the mock model generation script to create models on disk
.venv\Scripts\python.exe generate_mock_models.py

# 2. Configure environment variables
$env:MODEL_TYPE="object_detection"
$env:MODEL_PATH="models/object_detection_model_v2.pkl"
$env:MODEL_ADAPTER="ObjectDetectionAdapter"
$env:INPUT_TYPE="image"
$env:DETECTION_NAME="Generic Object Detection"
$env:MODEL_VERSION="1.0.0"

# 3. Start the Flask application
.venv\Scripts\python.exe run.py
```

Open a web browser and navigate to `http://127.0.0.1:5000` to interact with the application.

---

## 15. Testing
The repository contains automated tests that validate model initialization, route loading, database transactions, and model hot-swapping:

```powershell
# Run the reusability unit test suite
.venv\Scripts\python.exe -m unittest test_boilerplate_reusability.py
```

*Verification Status: All 6/6 tests in the reusability suite are verified and passing.*

---

## 16. Adding a New Model
To integrate a custom machine learning model:

1.  **Save Artifact**: Place the serialized model binary (e.g., joblib/pickle file) in the `models/` directory.
2.  **Define/Select Adapter**: If the model has standard scikit-learn interfaces (`predict`/`predict_proba`), select one of the existing adapters in `adapters.py`. If it has custom inputs/outputs, extend `BaseModelAdapter` and implement `preprocess()`, `predict()`, and `postprocess()`.
3.  **Update Variables**: Configure the environment settings (`MODEL_PATH`, `MODEL_ADAPTER`, `MODEL_TYPE`, `INPUT_TYPE`) to bind your model.
4.  **Confirm Contracts**: Verify that the adapter's output matches the `PredictionResult` expectations (`label`, `confidence`, and optional `metadata`).
5.  **Add Test Coverage**: Add a test method inside `test_boilerplate_reusability.py` to prevent regression.

---

## 17. Example Use Cases
Because the application is configuration-driven, you can reuse the same codebase for various tasks:
- **Tomato Disease Detection**: Use `ImageClassificationAdapter` with input type `image`. User uploads an image of a tomato leaf, and the model classifies it (e.g., "Tomato Early Blight", "Healthy").
- **Emotion Detection**: Use `TextClassificationAdapter` with input type `text` (for text sentiment inputs) or `ImageClassificationAdapter` (for facial expressions).
- **Fruit Detection**: Use `ObjectDetectionAdapter` with input type `image`. The model predicts coordinates and classes (e.g., "Apple", "Orange").
- **Human/Object Detection**: Use `ObjectDetectionAdapter` to identify humans, vehicles, or animals in images or video frames.
- **Text Classification**: Use `TextClassificationAdapter` to build a spam email detector, toxic comment classifier, or a support ticket router.
- **Tabular Prediction**: Use `TabularClassificationAdapter` to deploy tabular predictors like customer churn classifiers or risk score models.

---

## 18. Design Principles
- **Separation of Application and ML Model**: Core web layers (auth, DB, templates, files upload) are isolated from model runtimes.
- **Adapter Pattern**: A standardized interface decouples Flask logic from various frameworks and model interfaces.
- **Configuration-Driven Model Selection**: Environment variables drive adapter loading, input views, and model paths.
- **Standardized Prediction Result**: Standardized internal object contracts prevent database schema adjustments on model swap.
- **Reusable Frontend/Backend**: Form views render tabular fields dynamically based on config files, and the detection UI automatically scales based on JSON response arrays.
- **Testability**: Regression checks ensure model swaps are structurally safe.

---

## 19. Current Validation
- **6/6 tests passing** in the reusability unit test suite.
- **Tabular model swapping** verified (Model A to A2 swaps successfully, changing predictions).
- **Object detection model swapping** verified (Model V1 to V2 swaps successfully, changing labels and box coordinates).
- **Object detection bounding-box UI verified** (bounding boxes extracted from `metadata_json` are rendered dynamically on the user interface Canvas).

---

## 20. Limitations / Future Work
- **Mock Model Simplification**: Included mock models are for verification and pipeline demonstration. They must be replaced with fully trained models in production.
- **Deep Learning Dependencies**: Large machine learning models (e.g., PyTorch, TensorFlow, YOLO) may require extensive native library dependencies, large container builds, and GPU/CUDA setups not configured by default in this template's base setup.
- **Production Server Deployment**: The current configuration is optimized for development. Production deployments require a WSGI server wrapper (e.g. Gunicorn/uWSGI) behind a reverse proxy (e.g. Nginx) with secure SSL and secrets management.
- **Model Registry Integration**: Integration with enterprise registry systems (e.g. MLflow or DVC) could be added to manage and track binary lifecycles.
