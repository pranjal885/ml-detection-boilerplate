import os
from app import create_app

# Instantiate the Flask application
app = create_app()

if __name__ == '__main__':
    # Retrieve configuration parameters
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    debug = os.environ.get('FLASK_DEBUG', '0').lower() in {'1', 'true', 'yes', 'on'}

    # Run the server locally; production deployment should use Gunicorn instead.
    app.run(host=host, port=port, debug=debug)
