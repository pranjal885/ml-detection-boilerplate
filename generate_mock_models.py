import os
import json
import joblib

from app.services.mock_models import MockObjectDetectorV2

os.makedirs("models", exist_ok=True)

detector = MockObjectDetectorV2()

joblib.dump(
    detector,
    "models/object_detection_model_v2.pkl"
)

with open("models/object_detection_config_v2.json", "w") as f:
    json.dump({"features": []}, f)

print("Successfully generated mock object detection V2 model on disk!")