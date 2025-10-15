import joblib
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
)


FLOW_MODEL_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Max",
    "Idle Min",
]

ATTACK_MAPPING = {
    0: "Bots",
    1: "Brute Force",
    2: "DDoS",
    3: "DoS",
    4: "Normal Traffic",
    5: "Port Scanning",
    6: "Web Attacks",
}

FLOW_MODEL_PATH = "./service/models/flow/cicflowmeter.joblib"
PAYLOAD_MODEL_PATH = "./service/models/payload/distilbert_sql"

FLOW_MODEL = None
PAYLOAD_MODEL = None
PAYLOAD_TOKENIZER = None

try:
    FLOW_MODEL = joblib.load(FLOW_MODEL_PATH)
except FileNotFoundError:
    print(f"Flow model not found at {FLOW_MODEL_PATH}")
except Exception as exc:
    raise RuntimeError(
        "An unexpected error has occured while trying to load the flow model"
    )

try:
    PAYLOAD_MODEL = DistilBertForSequenceClassification.from_pretrained(
        PAYLOAD_MODEL_PATH
    )
    PAYLOAD_TOKENIZER = DistilBertTokenizer.from_pretrained(PAYLOAD_MODEL_PATH)
except FileNotFoundError:
    print(f"Payload model not found at {PAYLOAD_MODEL_PATH}")
except Exception as exc:
    raise RuntimeError(
        "An unexpected error has occured while trying to load the payload model"
    )


CONFIDENCE_THRESH = 0.90

PAYLOAD_MAX_LEN = 512
