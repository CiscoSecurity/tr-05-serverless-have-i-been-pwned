import json
import time
from http import HTTPStatus
from typing import Optional
from urllib.parse import quote

import requests
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        return {}


def get_key() -> Optional[str]:
    return get_jwt().get('key')  # HIBP_API_KEY


def fetch_breaches(key, email, truncate=False):
    if key is None:
        # Use the corresponding HIBP API error message.
        error = {
            'code': 'access denied',
            'message': 'Access denied due to missing hibp-api-key.',
        }
        return None, error

    url = current_app.config['HIBP_API_URL'].format(
        email=quote(email, safe=''),
        truncate=str(truncate).lower(),
    )

    headers = {
        'user-agent': 'Threat Response',
        'hibp-api-key': key,
    }

    response = requests.get(url, headers=headers)

    if response.status_code == HTTPStatus.UNAUTHORIZED:
        # Use the corresponding HIBP API error message.
        error = {
            'code': 'access denied',
            'message': 'Access denied due to improperly formed hibp-api-key.',
        }
        return None, error

    if response.status_code == HTTPStatus.NOT_FOUND:
        return [], None

    if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
        # Try again after some timeout suggested by the HIBP API.
        timeout = int(response.headers['retry-after'])
        time.sleep(timeout)
        return fetch_breaches(key, email, truncate=truncate)

    assert response.status_code == HTTPStatus.OK

    return response.json(), None


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    error = schema.validate(data) or None
    if error:
        data = None
        error = {
            'code': 'invalid payload',
            'message': f'Invalid JSON payload received. {json.dumps(error)}.',
        }

    return data, error


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(error):
    # According to the official documentation, an error here means that the
    # corresponding TR module is in an incorrect state and needs to be
    # reconfigured:
    # https://visibility.amp.cisco.com/help/alerts-errors-warnings.
    error['type'] = 'fatal'

    return jsonify({'errors': [error]})
