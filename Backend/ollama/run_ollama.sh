#!/bin/bash
set -e

# Start Ollama server in the background for model pulling
echo "Starting Ollama server temporarily for model pull..."
ollama serve &
OLLAMA_PID=$! # Store the PID of the background ollama serve process

# Wait for Ollama server to be accessible
echo "Waiting for Ollama server to be active..."
while ! curl -s http://localhost:11434 > /dev/null; do
  sleep 1
done
echo "Ollama server is active."

# Pull the desired model
echo "Pulling deepseek-r1:1.5b..."
# Optional: Add a check to only pull if the model isn't already present
# if ! ollama list | grep -q "deepseek-r1:1.5b"; then
#   ollama pull deepseek-r1:1.5b
# else
#   echo "deepseek-r1:1.5b is already present. Skipping pull."
# fi
ollama pull deepseek-r1:1.5b

echo "Model pull complete."

# IMPORTANT: Kill the background ollama serve process
echo "Stopping temporary Ollama server..."
kill $OLLAMA_PID
wait $OLLAMA_PID || true # Wait for it to exit, '|| true' prevents error if it's already gone

# Now, start the main Ollama server process in the foreground
# This process will take over PID 1 and keep the container alive.
echo "Starting main Ollama server..."
exec ollama serve