import torch
from pandas import DataFrame
import numpy as np

from service.core.settings import (
    FLOW_MODEL_FEATURES,
    ATTACK_MAPPING,
    FLOW_MODEL,
    PAYLOAD_MODEL,
    PAYLOAD_TOKENIZER,
    CONFIDENCE_THRESH,
    PAYLOAD_MAX_LEN,
)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


def predict_flow(features: dict):
    """Predicts what kind of network flow attack the input is from,
    expects the input to be a dictionary of feature name + value pairs"""
    if not isinstance(features, dict):
        raise ValueError("Flow model input is not a dictionary")
    if set(features.keys()) != set(FLOW_MODEL_FEATURES):
        raise ValueError("Flow model input doesn't have the right features")

    ordered_values = [features[feature] for feature in FLOW_MODEL_FEATURES]
    test = DataFrame([ordered_values], columns=FLOW_MODEL_FEATURES)

    probabilities = FLOW_MODEL.predict_proba(test)
    confidence = np.max(probabilities)
    predicted_attack = ATTACK_MAPPING[np.argmax(probabilities)]

    result = {"Attack Type": "Unknown", "confidence_score": confidence}
    if confidence >= CONFIDENCE_THRESH:
        result["Attack Type"] = predicted_attack
    else:
        # Low confidence: Reject the result
        print(
            f"Prediction rejected: Confidence was {confidence:.2f}, below threshold {CONFIDENCE_THRESH}."
        )
    return result


def predict_payload(sentence):
    """Predicts if the input SQL injection is benign or malicious"""
    if not isinstance(sentence, str):
        raise ValueError("Flow model input is not a string")
    # Tokenize
    inputs = PAYLOAD_TOKENIZER(
        sentence,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=PAYLOAD_MAX_LEN,
    )
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    # Predict
    with torch.no_grad():
        outputs = PAYLOAD_MODEL(**inputs)
        prediction = torch.argmax(outputs.logits, dim=1).item()
        probabilities = torch.nn.functional.softmax(outputs.logits, dim=1)[0]

    classification = "Malicious" if prediction == 1 else "Benign"
    confidence = probabilities[prediction].item() * 100
    return {"SQL Injection": classification, "confidence": confidence}
