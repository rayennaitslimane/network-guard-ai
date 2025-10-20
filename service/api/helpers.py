from datetime import datetime, timezone
import time
import uuid
from flask import g, request, jsonify
from functools import wraps
import json
import jwt

from service.core.config import FLOW_MODEL_NAME, PAYLOAD_MODEL_NAME
from service.core.inference import predict_flow, predict_payload


def make_require_auth(redis_client, app):

    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Authorization token required"}), 401

            # Extract the raw token
            token = auth_header.split(" ")[1]
            # Check blacklist using the RAW token
            if redis_client.exists(f"blacklist:{token}"):
                return jsonify({"error": "Token revoked"}), 401
            try:
                # Decode using the RAW token
                decoded = jwt.decode(
                    token, app.config["SECRET_KEY"], algorithms=["HS256"]
                )
                g.user_id = decoded.get("user_id")
            except Exception:
                return jsonify({"error": "Invalid or expired token"}), 401
            return f(*args, **kwargs)

        return decorated

    return require_auth


def get_user_by_email(redis_client, email):
    """O(1) lookup: email -> user_id stored as a simple key; 'users' is a hash that stores
    a single JSON string per user_id (hget returns that single field)."""
    user_id = redis_client.get(f"user:email:{email}")
    if not user_id:
        return None
    user_data = redis_client.hget("users", user_id)
    return json.loads(user_data) if user_data else None


def get_auth_user(redis_client):
    # Use authenticated user ID from JWT (never trust client-provided user_id)
    owner_id = g.get("user_id")
    if not owner_id:
        return None
    # Verify user exists in Redis
    user_record = redis_client.hget("users", owner_id)
    if not user_record:
        return None
    return owner_id


def process_inference_request(owner_id, data):
    if not data:
        return None, "Request body is required"
    model_name = data.get("model_name", "")
    if not model_name or len(model_name) > 100:
        return None, "Model name is required and must be <= 100 chars"

    features_dict = data.get("features_list", {})
    features_list = list(features_dict.values())
    if not features_list:
        return None, "Features list must be non empty"
    if not all(bool(d) for d in features_list):
        return None, "Features must be a dict"

    start_ts = time.time()
    if model_name == FLOW_MODEL_NAME:
        result = predict_flow(features_list)
    elif model_name == PAYLOAD_MODEL_NAME:
        result = predict_payload(features_list)
    else:
        raise ValueError(
            f"Invalid model name, must be either {FLOW_MODEL_NAME} or {PAYLOAD_MODEL_NAME}"
        )
    inference_ms = int((time.time() - start_ts) * 1000)

    mapped_result = dict(zip(features_dict.keys(), result))

    response_id = str(uuid.uuid4())
    response_payload = {
        "response_id": response_id,
        "model_name": model_name,
        "user_id": owner_id,
        "inference_ms": inference_ms,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": mapped_result,
    }
    return response_payload, None
