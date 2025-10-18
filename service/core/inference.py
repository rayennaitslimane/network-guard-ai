from service.core.config import (
    FLOW_FEATURES,
    PAYLOAD_FEATURES,
    FLOW_MODEL,
    PAYLOAD_MODEL,
    MAX_INPUT_LEN,
)
import logging
import pandas as pd
import torch


def validate_features(features, expected):
    if not isinstance(features, dict):
        logging.error("Input is not a dict")
        raise TypeError("Input is not a dict")
    if set(features.keys()) != set(expected):
        logging.error("Input keys do not match expected features")
        raise ValueError("Input keys do not match expected features")


def predict_flow(features_list):
    if isinstance(features_list, dict):
        features_list = [features_list]

    for features in features_list:
        validate_features(features, FLOW_FEATURES)
    df = pd.DataFrame(features_list, columns=FLOW_FEATURES)
    predictions_int = FLOW_MODEL["model"].predict(df)
    predictions = FLOW_MODEL["encoder"].inverse_transform(predictions_int)

    result = predictions.tolist()
    logging.info(f"Flow model predictions: {result}")
    return result


def predict_payload(features_list):
    if isinstance(features_list, dict):
        features_list = [features_list]

    text_list = []
    for features in features_list:
        validate_features(features, PAYLOAD_FEATURES)
        text = ""
        for name in PAYLOAD_FEATURES:
            if features[name] is None:
                value = "NULL_" + name
            else:
                value = str(features[name])
            text += f"[{name}]: " + value + " "
        text_list.append(text.strip())

    tokenizer = PAYLOAD_MODEL["tokenizer"]
    model = PAYLOAD_MODEL["model"]

    encoded = tokenizer(
        text_list,
        padding="max_length",
        truncation=True,
        max_length=MAX_INPUT_LEN,
        return_tensors="pt",
    )

    device = next(model.parameters()).device
    inputs = {k: v.to(device) for k, v in encoded.items()}

    # Predict
    model.eval()
    with torch.no_grad():
        outputs = model(**inputs)
        preds = outputs.logits.argmax(dim=1)

    result = preds.cpu().tolist()
    result = ["Benign" if x == 0 else "Malicious" for x in result]
    logging.info(f"Payload model predictions: {result}")
    return result
