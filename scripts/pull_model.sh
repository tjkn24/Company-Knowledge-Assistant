#!/bin/bash
# scripts/pull_ollama_model.sh
# ==============================
# Pull the configured Ollama model after Docker starts.
# Run this once after: docker compose up ollama
#
# Usage:
#   chmod +x scripts/pull_ollama_model.sh
#   ./scripts/pull_ollama_model.sh

MODEL=${OLLAMA_MODEL:-mistral}
echo "Pulling Ollama model: $MODEL"
docker exec -it ollama ollama pull $MODEL
echo "Done. Model $MODEL is ready."
echo ""
echo "To use a different model, set OLLAMA_MODEL in your .env file."
echo "Other good models: phi3 (smaller/faster), llama3 (larger/smarter)"
