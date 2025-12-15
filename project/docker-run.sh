#!/bin/bash
# docker-run.sh - Convenience script for running the Docker container

# Build the image
echo "Building Docker image..."
docker-compose build

# Run interactive mode by default
echo "Starting email spoofing tool..."
docker-compose run --rm email-tool interactive