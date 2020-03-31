import abc
import uuid
from typing import Dict, Any

from markdownify import markdownify


JSON = Dict[str, Any]


class Mapping(abc.ABC):

    @classmethod
    @abc.abstractmethod
    def map(cls, *args, **kwargs) -> JSON:
        pass


CTIM_DEFAULTS = {
    'schema_version': '1.0.16',
}


class Indicator(Mapping):
    DEFAULTS = {
        'type': 'indicator',
        'producer': 'Have I Been Pwned',
        'source': 'Have I Been Pwned Breaches',
        'tlp': 'white',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, breach: JSON) -> JSON:
        indicator: JSON = cls.DEFAULTS.copy()

        indicator['id'] = f'transient:{uuid.uuid4()}'

        # `BreachDate` itself is just a date with no time (i.e. YYYY-MM-DD),
        # so make sure to add some time to make the date comply with ISO 8601.
        indicator['valid_time'] = {
            'start_time': breach['BreachDate'] + 'T00:00:00Z'
        }

        indicator['confidence'] = ['Medium', 'High'][breach['IsVerified']]

        # `Description` contains an overview of the breach represented in HTML,
        # so convert its contents to Markdown to make it comply with CTIM.
        indicator['description'] = markdownify(breach['Description'])

        indicator['severity'] = ['Medium', 'High'][
            breach['IsVerified'] and 'Passwords' in breach['DataClasses']
        ]

        indicator['short_description'] = breach['Title']

        indicator['tags'] = breach['DataClasses']

        indicator['title'] = breach['Name']

        return indicator


class Sighting(Mapping):
    DEFAULTS = {
        'type': 'sighting',
        'internal': False,
        'source': 'Have I Been Pwned',
        'title': 'Found on Have I Been Pwned',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(
        cls, breach: JSON, count: int, email: str, source_uri: str
    ) -> JSON:
        sighting: JSON = cls.DEFAULTS.copy()

        sighting['confidence'] = ['Medium', 'High'][breach['IsVerified']]

        sighting['count'] = count

        sighting['id'] = f'transient:{uuid.uuid4()}'

        # `BreachDate` itself is just a date with no time (i.e. YYYY-MM-DD),
        # so make sure to add some time to make the date comply with ISO 8601.
        sighting['observed_time'] = {
            'start_time': breach['BreachDate'] + 'T00:00:00Z'
        }

        sighting['description'] = (
            f'Email address present in {breach["Title"]} breach.'
        )

        sighting['observables'] = [{'type': 'email', 'value': email}]

        if breach['Domain']:
            sighting['relations'] = [{
                'origin': sighting['source'],
                'related': {'type': 'domain', 'value': breach['Domain']},
                'relation': 'Leaked_From',
                'source': {'type': 'email', 'value': email},
                'origin_uri': source_uri,
            }]

        sighting['severity'] = ['Medium', 'High'][
            breach['IsVerified'] and 'Passwords' in breach['DataClasses']
        ]

        sighting['source_uri'] = source_uri

        sighting['targets'] = [{
            'observables': sighting['observables'],
            'observed_time': sighting['observed_time'],
            'type': 'email',
        }]

        return sighting


class Relationship(Mapping):
    DEFAULTS = {
        'type': 'relationship',
        'relationship_type': 'sighting-of',
        **CTIM_DEFAULTS
    }

    @classmethod
    def map(cls, indicator: JSON, sighting: JSON) -> JSON:
        relationship: JSON = cls.DEFAULTS.copy()

        relationship['id'] = f'transient:{uuid.uuid4()}'

        relationship['source_ref'] = sighting['id']

        relationship['target_ref'] = indicator['id']

        return relationship
