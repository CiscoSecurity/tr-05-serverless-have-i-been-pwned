import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    HIBP_TEST_EMAIL = 'user@example.com'

    HIBP_API_URL = (
        'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
        '?truncateResponse={truncate}'
    )

    # HIBP returns 403 Forbidden "API request must include a user agent"
    # when using angle brackets, only round brackets are acceptable...
    HIBP_USER_AGENT = (
        'Cisco Threat Response Integrations '
        '(tr-integrations-support@cisco.com)'
    )

    HIBP_UI_URL = 'https://haveibeenpwned.com/account/{email}'
