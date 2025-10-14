import pytest

from service.core.detector import FLOW_MODEL_FEATURES, predict_flow, predict_payload

# Flow model tests


def test_predict_flow_input_not_dict():
    with pytest.raises(ValueError):
        predict_flow([1, 2, 3])
    with pytest.raises(ValueError):
        predict_flow({5, 8, 9})
    with pytest.raises(ValueError):
        predict_flow("Attack")


def test_predict_flow_incorrect_features():
    with pytest.raises(ValueError):
        predict_flow({"Attack": 23, "Remedy": 0.1, "Defense": 1.6})
    with pytest.raises(ValueError):
        predict_flow({"DDos": 23, "Web": 0.1, "Punch": 1.6})


def test_predict_flow_unknown_attacks():
    feat1 = {feature: 100000 for feature in FLOW_MODEL_FEATURES}
    res1 = predict_flow(feat1)
    assert res1["Attack Type"] == "Unknown"


def test_predict_flow_benign_attack():
    benign_features = {
        "Destination Port": 443,
        "Flow Duration": 1200000,
        "Total Fwd Packets": 10,
        "Total Length of Fwd Packets": 560,
        "Fwd Packet Length Max": 146,
        "Fwd Packet Length Min": 52,
        "Fwd Packet Length Mean": 78.88,
        "Fwd Packet Length Std": 30.15,
        "Bwd Packet Length Max": 1000,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 450.0,
        "Bwd Packet Length Std": 350.5,
        "Flow Bytes/s": 466.6666,
        "Flow Packets/s": 0.00001666,
        "Flow IAT Mean": 80000.0,
        "Flow IAT Std": 120000.0,
        "Flow IAT Max": 350000.0,
        "Flow IAT Min": 1000,
        "Fwd IAT Total": 1200000,
        "Fwd IAT Mean": 120000.0,
        "Fwd IAT Std": 150000.0,
        "Fwd IAT Max": 400000.0,
        "Fwd IAT Min": 1000,
        "Bwd IAT Total": 1000000,
        "Bwd IAT Mean": 142857.14,
        "Bwd IAT Std": 190000.0,
        "Bwd IAT Max": 500000.0,
        "Bwd IAT Min": 1000,
        "Fwd Header Length": 320,
        "Bwd Header Length": 300,
        "Fwd Packets/s": 0.00000833,
        "Bwd Packets/s": 0.00000833,
        "Min Packet Length": 0,
        "Max Packet Length": 1460,
        "Packet Length Mean": 300.55,
        "Packet Length Std": 390.87,
        "Packet Length Variance": 152778.0,
        "FIN Flag Count": 1,
        "PSH Flag Count": 4,
        "ACK Flag Count": 8,
        "Average Packet Size": 330.6,
        "Subflow Fwd Bytes": 560,
        "Init_Win_bytes_forward": 65535,
        "Init_Win_bytes_backward": 65535,
        "act_data_pkt_fwd": 7,
        "min_seg_size_forward": 20,
        "Active Mean": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Max": 0,
        "Idle Min": 0,
    }
    print("Benign Attack Test")
    res1 = predict_flow(benign_features)
    assert res1["Attack Type"] == "Normal Traffic"


def test_predict_flow_malicious_attack():
    malicious_features = {
        "Destination Port": 80,
        "Flow Duration": 4421382,
        "Total Fwd Packets": 4,
        "Total Length of Fwd Packets": 24,
        "Fwd Packet Length Max": 6,
        "Fwd Packet Length Min": 6,
        "Fwd Packet Length Mean": 6.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 5.42816703,
        "Flow Packets/s": 0.904694505,
        "Flow IAT Mean": 1473794.0,
        "Flow IAT Std": 2552042.631,
        "Flow IAT Max": 4420639,
        "Flow IAT Min": 340,
        "Fwd IAT Total": 4421382,
        "Fwd IAT Mean": 1473794.0,
        "Fwd IAT Std": 2552042.631,
        "Fwd IAT Max": 4420639,
        "Fwd IAT Min": 340,
        "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0.0,
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": 0,
        "Bwd IAT Min": 0,
        "Fwd Header Length": 80,
        "Bwd Header Length": 0,
        "Fwd Packets/s": 0.904694505,
        "Bwd Packets/s": 0.0,
        "Min Packet Length": 6,
        "Max Packet Length": 6,
        "Packet Length Mean": 6.0,
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 1,
        "Average Packet Size": 7.5,
        "Subflow Fwd Bytes": 24,
        "Init_Win_bytes_forward": 256,
        "Init_Win_bytes_backward": 1,
        "act_data_pkt_fwd": 3,
        "min_seg_size_forward": 20,
        "Active Mean": 0.0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0.0,
        "Idle Max": 0,
        "Idle Min": 0,
    }
    print("Benign Attack Test")
    res1 = predict_flow(malicious_features)
    assert res1["Attack Type"] == "DDoS"


# Payload model tests


def test_predict_payload_input_not_string():
    with pytest.raises(ValueError):
        predict_payload((1, 2, 3))
    with pytest.raises(ValueError):
        predict_payload({"Amazing": 5, "Incredible": 8, "Splendid": 9})
    with pytest.raises(ValueError):
        predict_payload(134.7)


def test_predict_payload_benign_sqli():
    benign_sentences = [
        "SELECT * FROM users WHERE username = 'admin'",
        "SELECT name, email FROM customers WHERE id = 5",
        "SELECT * FROM products WHERE category = 'electronics' AND price < 100",
    ]
    for sentence in benign_sentences:
        result = predict_payload(sentence)
        assert result["SQL Injection"] == "Benign"


def test_predict_payload_malicious_sqli():
    malicious_sentences = [
        "SELECT * FROM users WHERE id = 1 OR 1=1--",
        "'; DROP TABLE users; --",
        "1' UNION SELECT null, table_name FROM information_schema.tables--",
    ]
    for sentence in malicious_sentences:
        result = predict_payload(sentence)
        assert result["SQL Injection"] == "Malicious"
