from pydantic import BaseModel, EmailStr, ValidationError
from flask import request, jsonify
from datetime import datetime, timezone, timedelta
import jwt, json
from jwt import ExpiredSignatureError, InvalidTokenError
import uuid
from argon2.exceptions import VerifyMismatchError
import logging

from service.api.helpers import (
    get_user_by_email,
    get_auth_user,
    process_inference_request,
)


class UserCreateSchema(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


def make_api_routes(app, redis_client, ph, limiter, require_auth):

    @app.route("/health")
    def health_check():
        """Health check endpoint for load balancer"""
        return (
            jsonify(
                {
                    "status": "healthy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "port": app.config.get("PORT", "unknown"),
                }
            ),
            200,
        )

    @app.route("/users", methods=["POST"])
    @limiter.limit("5 per minute")
    def create_user():
        try:
            # Parse and validate input
            json_data = request.get_json()
            if not json_data:
                return jsonify({"error": "Request body is required"}), 400

            try:
                user_input = UserCreateSchema.model_validate(json_data)
            except ValidationError as ve:
                return jsonify({"error": ve.errors()}), 422

            # Sanitize inputs
            name = user_input.name
            email = user_input.email.lower()

            # Check if email already exists
            if redis_client.exists(f"user:email:{email}"):
                return jsonify({"error": "Email already exists"}), 409

            # Hash password
            hashed = ph.hash(user_input.password)

            # Create user record
            user_id = str(uuid.uuid4())
            user = {
                "id": user_id,
                "name": name,
                "email": email,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "password_hash": hashed,
            }

            # Persist in Redis
            redis_client.hset("users", user_id, json.dumps(user))
            redis_client.set(f"user:email:{email}", user_id)

            safe_user = {k: v for k, v in user.items() if k != "password_hash"}
            return (
                jsonify({"message": "User created successfully", "user": safe_user}),
                201,
            )

        except Exception as exp:
            logging.exception(exp)
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/login", methods=["POST"])
    @limiter.limit("10 per minute")
    def login():
        """Generate JWT for authenticated users"""
        json_data = request.get_json()
        if not json_data:
            return jsonify({"error": "Request body is required"}), 400

        try:
            data = LoginSchema.model_validate(json_data)
        except ValidationError as ve:
            return jsonify({"error": ve.errors()}), 422

        email = data.email.lower()

        # User validation
        user = get_user_by_email(redis_client, email)
        if not user:
            # Dummy hash verification to normalize timing
            try:
                ph.verify(app.config["DUMMY_PW_HASH"], data.password)
            except Exception as exp:
                logging.exception(exp)
                return jsonify({"error": "Internal server error"}), 500
            return jsonify({"error": "Invalid credentials"}), 401

        try:
            ph.verify(user["password_hash"], data.password)
        except VerifyMismatchError:
            return jsonify({"error": "Invalid credentials"}), 401
        except Exception as exp:
            logging.exception(exp)
            return jsonify({"error": "Internal server error"}), 500

        token = jwt.encode(
            {
                "user_id": user["id"],
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            },
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )

        return (
            jsonify(
                {
                    "message": "Authenticated",
                    "token": token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            ),
            200,
        )

    @app.route("/logout", methods=["POST"])
    @require_auth
    def logout():
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token required"}), 401
        token = auth_header.split(" ")[1]

        try:
            decoded_token = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"]
            )
        except ExpiredSignatureError:
            # Already expired — nothing to blacklist; still return success
            return jsonify({"message": "Logged out"}), 200
        except InvalidTokenError:
            # Invalid token — do not reveal details
            return jsonify({"message": "Logged out"}), 200

        exp_timestamp = int(decoded_token.get("exp", 0))
        now_ts = int(datetime.now(timezone.utc).timestamp())
        ttl = exp_timestamp - now_ts
        if ttl > 0:
            redis_client.setex(f"blacklist:{token}", ttl, "1")

        return jsonify({"message": "Logged out"}), 200

    @app.route("/inference", methods=["POST"])
    @limiter.limit("30 per minute")
    @require_auth
    def run_inference():
        owner_id = get_auth_user(redis_client)
        if not owner_id:
            return jsonify({"error": "User not found"}), 404

        data = request.get_json()
        inference_result, error = process_inference_request(owner_id, data)
        if error:
            return jsonify({"error": error}), 400

        # Use a per-user hash keyed by user_id
        redis_client.hset(
            f"inferences:{owner_id}",
            inference_result["response_id"],
            json.dumps(inference_result),
        )

        return jsonify(inference_result), 201

    @app.route("/inference", methods=["GET"])
    @limiter.limit("30 per minute")
    @require_auth
    def get_inference_trace():
        owner_id = get_auth_user(redis_client)
        if not owner_id:
            return jsonify({"error": "User not found"}), 404
        # Fetch all values directly from the per-user hash
        trace_json = redis_client.hvals(f"inferences:{owner_id}")
        trace = [json.loads(row) for row in trace_json]
        trace.sort(key=lambda x: x["created_at"])
        return jsonify({"trace": trace}), 200
