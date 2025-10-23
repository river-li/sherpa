#!/bin/bash

# Simple test script to run batch_generate_target.py with brotli benchmark
# This is similar to the 'make leveldb' target but for targeted fuzzing

set -e

# Load environment variables from .env file if it exists
if [ -f .env ]; then
  export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)
fi

# Check if OPENAI_API_KEY is set
if [ -z "$OPENAI_API_KEY" ]; then
  echo "Error: OPENAI_API_KEY is not set. Please export your OpenAI API key before running this script."
  exit 1
fi

# Check if Docker is running
docker info > /dev/null 2>&1 || (echo "Error: Docker is not running or not accessible. Please start Docker and try again." && exit 1)

# Activate virtual environment and run batch_generate_target.py
# max-retries=5: build_with_retry attempts within each harness generation
# The outer retry loop (3 attempts) is now built into batch_generate_target.py
. .venv/bin/activate && python harness_generator/batch_generate_target.py \
    --benchmark-file benchmark/brotli.yaml \
    --ai-key-path .env \
    --max-retries 5
