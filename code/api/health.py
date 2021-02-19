from flask import Blueprint, current_app

from api.utils import get_key, fetch_breaches, jsonify_errors, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    # Use some breached email just to check that the HIBP API key is valid.
    email = current_app.config['HIBP_TEST_EMAIL']
    _, error = fetch_breaches(key, email, truncate=True)

    if error:
        return jsonify_errors(error)
    else:
        return jsonify_data({'status': 'ok'})
