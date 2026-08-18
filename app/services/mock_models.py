class MockObjectDetector:
    def detect(self, X):
        return [
            {
                "box_2d": [40, 50, 400, 600],
                "label": "Person",
                "score": 0.94
            }
        ]

class MockObjectDetectorV2:
    def detect(self, X):
        return [
            {
                "box_2d": [80, 100, 450, 650],
                "label": "Dog",
                "score": 0.91
            }
        ]