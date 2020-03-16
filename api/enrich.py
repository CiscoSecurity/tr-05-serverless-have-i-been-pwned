from functools import partial

from flask import Blueprint

from api.schemas import ObservableSchema
from api.utils import get_json, jsonify_data

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # There are no verdicts to extract.
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    # TODO: extract indicators.
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # There are no references (i.e. clickable links) to show.
    return jsonify_data([])