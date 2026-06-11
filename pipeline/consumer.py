name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  # ── 1. Lint & type-check ───────────────────────────────────────────────────
  lint:
    name: Lint & Type Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install lint deps
        run: pip install ruff mypy pydantic

      - name: ruff (lint + format check)
        run: |
          ruff check .
          ruff format --check .

      - name: mypy (pipeline/consumer.py)
        run: mypy pipeline/consumer.py pipeline/metrics.py --ignore-missing-imports

  # ── 2. Unit tests ─────────────────────────────────────────────────────────
  test:
    name: Unit Tests (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-mock

      - name: Run tests with coverage
        run: |
          pytest tests/test_consumer.py -v \
            --cov=pipeline/consumer \
            --cov-report=xml \
            --cov-report=term-missing \
            --cov-fail-under=80

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          file: coverage.xml
          fail_ci_if_error: false

  # ── 3. Integration test (Kafka via docker-compose) ─────────────────────────
  integration:
    name: Integration Test
    runs-on: ubuntu-latest
    needs: test      # only run after unit tests pass

    services:
      zookeeper:
        image: confluentinc/cp-zookeeper:7.6.0
        env:
          ZOOKEEPER_CLIENT_PORT: 2181
        ports: ["2181:2181"]

      kafka:
        image: confluentinc/cp-kafka:7.6.0
        env:
          KAFKA_BROKER_ID: 1
          KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
          KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
          KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
          KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
        ports: ["9092:9092"]

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements.txt pytest

      - name: Wait for Kafka to be ready
        run: |
          for i in $(seq 1 30); do
            nc -z localhost 9092 && echo "Kafka ready" && break
            echo "Waiting for Kafka... ($i/30)"
            sleep 2
          done

      - name: Run integration tests
        env:
          KAFKA_BROKER: localhost:9092
        run: pytest tests/test_integration.py -v -m integration

  # ── 4. Docker build (smoke test) ──────────────────────────────────────────
  docker:
    name: Docker Build
    runs-on: ubuntu-latest
    needs: test

    steps:
      - uses: actions/checkout@v4

      - name: Build consumer image
        run: docker build -t netguard-consumer:ci -f Dockerfile.consumer .

      - name: Smoke-test image starts
        run: |
          docker run --rm \
            -e KAFKA_BROKER=localhost:9092 \
            --entrypoint python \
            netguard-consumer:ci \
            -c "from pipeline.consumer import process_message; print('import OK')"
