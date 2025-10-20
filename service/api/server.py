# Flask API Module
from flask import Flask
import argparse
import redis
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from argon2 import PasswordHasher

from service.api.helpers import make_require_auth
from service.api.routes import make_api_routes

ph = PasswordHasher()

app = Flask(__name__)

# Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback-insecure-key")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# Timing-attack-resistant dummy verification (server startup: create a stable dummy hash)
_dummy_pw = os.getenv("DUMMY_PW_PLAINTEXT", "change-this-default")
app.config["DUMMY_PW_HASH"] = ph.hash(_dummy_pw)


# Redis connection with authentication and TLS
use_ssl = os.getenv("REDIS_USE_SSL", "false").lower() == "true"
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=int(os.getenv("REDIS_DB", 0)),
    password=REDIS_PASSWORD,
    ssl=use_ssl,
    ssl_cert_reqs=None if not use_ssl else "required",
    decode_responses=True,
)

# Rate limiter setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per minute"],
)

# Create the routes
require_auth = make_require_auth(redis_client, app)

make_api_routes(app, redis_client, ph, limiter, require_auth)

# Parser config
parser = argparse.ArgumentParser(description="Run API server")
parser.add_argument("--port", type=int, default=5001, help="Port to run the server on")
parser.add_argument(
    "--host", type=str, default="0.0.0.0", help="Host to run the server on"
)

args = parser.parse_args()

app.config["PORT"] = args.port

print(f"Starting API server on {args.host}:{args.port}")
# For HTTPS, configure SSL in production (via Nginx or app.run(ssl_context='adhoc'))
app.run(host=args.host, port=args.port, debug=False)
