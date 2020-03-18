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

    HIBP_USER_AGENT = 'Cisco Threat Response'
