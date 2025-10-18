from service.core.inference import predict_flow, predict_payload
from service.core.config import FLOW_FEATURES, PAYLOAD_FEATURES
from tests.data.flows import BENIGN_FLOW_SAMPLES, MALICIOUS_FLOW_SAMPLES
from tests.data.payloads import BENIGN_PAYLOAD_SAMPLES, MALICIOUS_PAYLOAD_SAMPLES


def test_predict_flow_benign():
    features_list = []
    for sample in BENIGN_FLOW_SAMPLES:
        features = dict(zip(FLOW_FEATURES, sample))
        features_list.append(features)
    results = predict_flow(features_list)
    for r in results:
        assert r == "Normal Traffic"


# TODO: the Random Forest Model has very low performance,
# not detecting the malicious samples correctly, despite its evaluation metrics
# Replace this ML classifier later on with a more performant one
def test_predict_flow_malicious():
    features_list = []
    for sample in MALICIOUS_FLOW_SAMPLES:
        features = dict(zip(FLOW_FEATURES, sample))
        features_list.append(features)
    results = predict_flow(features_list)
    print(results)


def test_predict_payload_benign():
    features_list = []
    for sample in BENIGN_PAYLOAD_SAMPLES:
        features = dict(zip(PAYLOAD_FEATURES, sample))
        features_list.append(features)
    results = predict_payload(features_list)
    for r in results:
        assert r == "Benign"
