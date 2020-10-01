from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import MODULE_NAME


def test_positive_smoke_empty_observable(module_headers):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which Have I Been Pwned doesn't have information, will
     return empty data

    ID: CCTRI-1695-b98d1d01-fd20-492f-bda5-bafb313a0737

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains empty dict from
         Have I Been Pwned

    Importance: Critical
    """
    observable = [{'type': 'email', 'value': 'empty@empty.org'}]
    response_from_all_modules = enrich_observe_observables(
        payload=observable,
        **{'headers': module_headers}
    )

    hibp_data = response_from_all_modules['data']

    response_from_hibp_module = get_observables(hibp_data, MODULE_NAME)

    assert response_from_hibp_module['module'] == MODULE_NAME
    assert response_from_hibp_module['module_instance_id']
    assert response_from_hibp_module['module_type_id']

    assert response_from_hibp_module['data'] == {}
