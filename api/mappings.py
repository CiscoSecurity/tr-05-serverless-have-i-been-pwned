import abc
import uuid


class Mapping(abc.ABC):

    @classmethod
    @abc.abstractmethod
    def map(cls, email, breach):
        pass


class Indicator(Mapping):
    DEFAULTS = {
        'type': 'indicator',
        'schema_version': '1.0.16',
        'source': 'Have I Been Pwned',
        'source_uri': 'https://haveibeenpwned.com',
        'producer': 'Have I Been Pwned',
        'tlp': 'white',
    }

    @classmethod
    def map(cls, email, breach):
        indicator = cls.DEFAULTS.copy()

        indicator['id'] = f'transient:{uuid.uuid4()}'

        # `BreachDate` itself is just a date with no time (i.e. YYYY-MM-DD),
        # so make sure to add some time to make the date comply with ISO 8601.
        indicator['valid_time'] = {
            'start_time': breach['BreachDate'] + 'T00:00:00Z'
        }

        indicator['confidence'] = ['Medium', 'High'][breach['IsVerified']]

        indicator['description'] = breach['Description']

        indicator['severity'] = ['Medium', 'High'][
            breach['IsVerified'] and 'Passwords' in breach['DataClasses']
        ]

        indicator['short_description'] = breach['Title']

        indicator['tags'] = breach['DataClasses']

        indicator['title'] = breach['Name']

        return indicator
