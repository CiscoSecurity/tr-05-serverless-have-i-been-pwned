from flask import Blueprint

from api.utils import get_key, fetch_breaches, jsonify_errors, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    key = get_key()

    # Use some breached email just to check that the HIBP API key is valid.
    _, error = fetch_breaches(key, 'user@example.com', truncate=True)

    if error:
        return jsonify_errors(error)
    else:
        return jsonify_data({'status': 'ok'})
