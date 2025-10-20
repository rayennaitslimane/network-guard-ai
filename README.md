# Network Guard AI

**Network Guard AI** is an AI-powered network intrusion detection system built with machine learning and transformer technology. 

It monitors network traffic in near real time and flags malicious activities such as DDoS, port scanning, SQL injection, brute force attacks, and other anomalies. 

A machine learning model is trained on the **CIC-IDS2017 Network Flow** dataset, and a transformer issued from HuggingFace is fine tuned on the **CSIC-2010 Web Attacks** used together to improve detection across multiple attack types.

## Getting started
- Install deps:
  ```sh
  pip install -r requirements.txt
  ```
  (see requirements.txt)

## Run the API Server

Before starting the API, make sure Redis is running, since user authentication and inference tracing depend on it.

If Redis isn’t already running:
```sh
sudo service redis-server start
````

Check its status:

```sh
sudo service redis-server status
```

Verify it’s responding (you should see PONG):

```sh
redis-cli ping
```

Once Redis is running, start the Network Guard AI API server:

```sh
python -m service.api.server --host 0.0.0.0 --port 5001
```

This launches the API on port **5001**.
If you open another terminal, you can test endpoints such as `/health`, `/users`, and `/login` using `curl` or Postman.

## Quick model usage

- Flow classifier
  - Features list is defined in `service.core.config.FLOW_FEATURES`.
  - Use the flow predictor: `service.core.inference.predict_flow`.

  Example:
  ```python
  from service.core.config import FLOW_FEATURES
  from service.core.inference import predict_flow

  sample = dict(zip(FLOW_FEATURES, [0]*len(FLOW_FEATURES)))
  print(predict_flow(sample))
  ```

- Payload classifier (text)
  - Features list is defined in `service.core.config.PAYLOAD_FEATURES`.
  - Use the payload predictor: `service.core.inference.predict_payload`.

  Example:
  ```python
  from service.core.config import PAYLOAD_FEATURES
  from service.core.inference import predict_payload

  sample = dict(zip(PAYLOAD_FEATURES, [""]*len(PAYLOAD_FEATURES)))
  print(predict_payload(sample))
  ```

## Run tests
- Run the unit tests with:
  ```sh
  pytest -q
  ```
  Tests for inference are in test_inference.py.


## Configuration & models
- Core config and model-loading constants: `service.core.config` (e.g. `service.core.config.MAX_INPUT_LEN`, `service.core.config.FLOW_MODEL`, `service.core.config.PAYLOAD_MODEL`).
- Inference functions and input validation: `service.core.inference.validate_features`, `service.core.inference.predict_flow`, `service.core.inference.predict_payload`.
- Built models and feature lists are under:
  - flow
  - payload
  - features

## Notes
- The functions expect a dict (or list of dicts) whose keys exactly match the respective FEATURES lists; mismatches raise errors (see `service.core.inference.validate_features`).
- Tests and examples assume the model artifacts referenced in `service.core.config` exist under the models tree.

## Roadmap

- Implement the api (routes, load balancer)
- Implement a capture simulator allowing to perform integration tests across the pipeline

## License & Contact
- Project contains local model artifacts and notebooks; follow their respective licensing (see model READMEs like models/payload/distilbert-fine-tuned-csic2010/README.md).

* **Author:** Rayen Nait Slimane
* **Contact:** [rayennaitslimane@gmail.com](mailto:rayennaitslimane@gmail.com)
