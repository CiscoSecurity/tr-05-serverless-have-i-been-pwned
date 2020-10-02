from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    HIBP_URL,
    CTR_ENTITIES_LIMIT
)


def test_positive_sighting_email(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sighting for observable from Have I Been Pwned module

    ID: CCTRI-812-57f2d8d6-a897-4ce4-abcf-331296e2d86a

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sighting for
            observable from Have I Been Pwned module

    Importance: Critical
    """
    observable = [{'type': 'email', 'value': 'test@test.com'}]
    response = enrich_observe_observables(
        payload=observable,
        **{'headers': module_headers}
    )['data']
    sightings = get_observables(
        response, 'Have I Been Pwned')['data']['sightings']
    assert len(sightings['docs']) > 0
    # check some generic properties
    for sighting in sightings['docs']:
        assert sighting['type'] == 'sighting'
        assert sighting['count'] == 1
        assert sighting['internal'] is False
        assert sighting['title'] == f'Found on {MODULE_NAME}'
        assert sighting['observables'] == observable
        assert sighting['source'] == MODULE_NAME
        assert sighting['source_uri'] == (
            f'{HIBP_URL}/account/test%40test.com'
        )
        assert sighting['targets'][0]['type'] == 'email'
        assert sighting['targets'][0]['observables'] == observable
        assert sighting['observed_time']['start_time'] == (
            sighting['observed_time']['end_time']
        )
    assert sightings['count'] == len(sightings['docs']) <= CTR_ENTITIES_LIMIT
    # check properties of one unique sighting
    sighting = [
        d for d in sightings['docs'] if 'Apollo' in d['description']][0]
    assert sighting['description'] == (
        f'{observable[0]["value"]} present in Apollo breach.'
    )
    relation = {
        'origin': MODULE_NAME,
        'origin_uri': f'{HIBP_URL}/account/test%40test.com',
        'relation': 'Leaked_From',
        'source': observable[0],
        'related': {'value': 'apollo.io', 'type': 'domain'}
    }
    assert sighting['relations'][0] == relation
    assert sighting['confidence'] == 'High'
    assert sighting['severity'] == 'Medium'
