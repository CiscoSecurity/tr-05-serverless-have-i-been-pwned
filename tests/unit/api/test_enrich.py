from http import HTTPStatus
from unittest import mock
from urllib.parse import quote

from authlib.jose import jwt
from pytest import fixture

from api.mappings import Indicator
from .utils import headers


def routes():
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': ''}]


def test_enrich_call_with_invalid_json_failure(route, client, invalid_json):
    response = client.post(route, json=invalid_json)

    # The actual error message is quite unwieldy, so let's just ignore it.
    expected_payload = {
        'errors': [
            {
                'code': 'invalid payload received',
                'message': mock.ANY,
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


@fixture(scope='module')
def valid_json():
    return [
        {
            'type': 'email',
            'value': 'dummy@cisco.com',
        },
        {
            'type': 'email',
            'value': 'dummy@gmail.com',
        },
        {
            'type': 'ip',
            'value': '8.8.8.8',
        },
        {
            'type': 'sha256',
            'value': '01' * 32,
        },
        {
            'type': 'file_name',
            'value': 'danger.exe',
        }
    ]


def test_enrich_call_with_valid_json_but_invalid_jwt_failure(route,
                                                             client,
                                                             valid_json,
                                                             invalid_jwt):
    response = client.post(route,
                           json=valid_json,
                           headers=headers(invalid_jwt))

    expected_payload = {
        'errors': [
            {
                'code': 'access denied',
                'message': 'Access to HIBP denied due to invalid API key.',
                'type': 'fatal',
            }
        ]
    }

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def all_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=all_routes(),
         ids=lambda route: f'POST {route}')
def any_route(request):
    return request.param


@fixture(scope='function')
def hibp_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def hibp_api_response(status_code):
    mock_response = mock.MagicMock()

    mock_response.status_code = status_code

    if status_code == HTTPStatus.OK:
        payload_list = [
            [],
            [
                {
                    'Name': 'From "Name" to "title".',
                    'Title': 'From "Title" to "short_description".',
                    'BreachDate': '1970-01-01',
                    'Description': 'From "Description" to "description".',
                    'DataClasses': ['From "DataClasses" to "tags".'],
                    'IsVerified': True,
                },
            ],
        ]

        payloads_list_iter = iter(payload_list)

        mock_response.json = lambda: next(payloads_list_iter)

    return mock_response


@fixture(scope='module')
def expected_payload(any_route):
    payload = None

    if any_route.startswith('/deliberate'):
        payload = {}

    if any_route.startswith('/observe'):
        payload = {
            'indicators': {
                'count': 1,
                'docs': [
                    {
                        'confidence': 'High',
                        'description': 'From "Description" to "description".',
                        'id': mock.ANY,
                        'severity': 'Medium',
                        'short_description': (
                            'From "Title" to "short_description".'
                        ),
                        'tags': ['From "DataClasses" to "tags".'],
                        'title': 'From "Name" to "title".',
                        'valid_time': {'start_time': '1970-01-01T00:00:00Z'},
                        **Indicator.DEFAULTS
                    },
                ],
            },
        }

    if any_route.startswith('/refer'):
        payload = []

    return {'data': payload}


def test_enrich_call_success(any_route,
                             client,
                             valid_json,
                             hibp_api_request,
                             valid_jwt,
                             expected_payload):
    app = client.application

    if any_route in routes():
        hibp_api_request.return_value = hibp_api_response(HTTPStatus.OK)

        response = client.post(any_route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        emails = [
            observable['value']
            for observable in valid_json
            if observable['type'] == 'email'
        ]

        expected_urls = [
            app.config['HIBP_API_URL'].format(
                email=quote(email, safe=''),
                truncate='false',
            )
            for email in emails
        ]

        expected_headers = {
            'user-agent': app.config['HIBP_USER_AGENT'],
            'hibp-api-key': (
                jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
            ),
        }

        hibp_api_request.assert_has_calls([
            mock.call(expected_url, headers=expected_headers)
            for expected_url in expected_urls
        ])

    else:
        response = client.post(any_route)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_enrich_call_with_external_error_from_hibp_failure(route,
                                                           client,
                                                           valid_json,
                                                           hibp_api_request,
                                                           valid_jwt):
    for status_code, error_code, error_message in [
        (
            HTTPStatus.UNAUTHORIZED,
            'access denied',
            'Access to HIBP denied due to invalid API key.',
        ),
        (
            HTTPStatus.SERVICE_UNAVAILABLE,
            'service unavailable',
            'Service temporarily unavailable. Please try again later.',
        ),
    ]:
        app = client.application

        hibp_api_request.return_value = hibp_api_response(status_code)

        response = client.post(route,
                               json=valid_json,
                               headers=headers(valid_jwt))

        email = next(
            observable['value']
            for observable in valid_json
            if observable['type'] == 'email'
        )

        expected_url = app.config['HIBP_API_URL'].format(
            email=quote(email, safe=''),
            truncate='false',
        )

        expected_headers = {
            'user-agent': app.config['HIBP_USER_AGENT'],
            'hibp-api-key': (
                jwt.decode(valid_jwt, app.config['SECRET_KEY'])['key']
            ),
        }

        hibp_api_request.assert_called_once_with(expected_url,
                                                 headers=expected_headers)

        hibp_api_request.reset_mock()

        expected_payload = {
            'errors': [
                {
                    'code': error_code,
                    'message': error_message,
                    'type': 'fatal',
                }
            ]
        }

        assert response.status_code == HTTPStatus.OK
        assert response.get_json() == expected_payload
