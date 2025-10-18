from transformers import AutoTokenizer, AutoModelForSequenceClassification
from peft import PeftModel
import joblib
import logging

if not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

print("logger configured")

FLOW_DIR = "models/flow/"
PAYLOAD_DIR = "models/payload/"
FEATURES_DIR = "models/features/"

FLOW_MODEL_NAME = "random-forest-cicids2017"
PAYLOAD_MODEL_NAME = "distilbert-fine-tuned-csic2010"


def load_features(path):
    try:
        with open(path, "r", encoding="UTF-8") as file:
            features = file.read().strip().split(",")
            return features
    except FileNotFoundError:
        logging.error(f"No features csv found at {path} !")
        raise
    except Exception as exp:
        logging.exception(f"An error occurred during loading: {exp}")
        raise


FLOW_FEATURES = load_features(FEATURES_DIR + FLOW_MODEL_NAME + ".csv")
PAYLOAD_FEATURES = load_features(FEATURES_DIR + PAYLOAD_MODEL_NAME + ".csv")

print("features loaded")


def load_model(path, method):
    try:
        model = method(path)
        return model
    except FileNotFoundError:
        logging.error(f"No model found at {path} !")
        raise
    except Exception as exp:
        logging.exception(f"An error occurred during loading: {exp}")
        raise


def load_joblib(path):
    return joblib.load(path)


MAX_INPUT_LEN = 128
NUM_LABELS = 2
MODEL_NAME = "distilbert-base-uncased"


def load_peft_lora_transformer(path):
    """
    Load a transformer model with PEFT LoRA weights.

    model_name: Base model name/path (e.g., 'meta-llama/Llama-2-7b-hf')
    lora_weights_path: Path to LoRA adapter weights
    device: Device to load model on ('cuda' or 'cpu')

    Returns model with LoRA weights merged
    """
    base_model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, num_labels=NUM_LABELS, device_map="auto"
    )
    model = PeftModel.from_pretrained(base_model, path)
    model = model.merge_and_unload()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    return {"model": model, "tokenizer": tokenizer}


FLOW_MODEL = {}
FLOW_MODEL["model"] = load_model(FLOW_DIR + FLOW_MODEL_NAME + ".joblib", load_joblib)
FLOW_MODEL["encoder"] = load_model(
    FLOW_DIR + FLOW_MODEL_NAME + "-encoder.joblib", load_joblib
)
PAYLOAD_MODEL = load_model(PAYLOAD_DIR + PAYLOAD_MODEL_NAME, load_peft_lora_transformer)

print("models loaded")
