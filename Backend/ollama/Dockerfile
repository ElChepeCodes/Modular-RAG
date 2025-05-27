# Use the official Ollama base image
FROM ollama/ollama:latest

RUN apt-get update && apt-get install -y curl

# Copy your entrypoint script into the container
COPY run_ollama.sh /usr/local/bin/run_ollama.sh

# Make the script executable
RUN chmod +x /usr/local/bin/run_ollama.sh

# Set the entrypoint to your script
ENTRYPOINT ["/usr/local/bin/run_ollama.sh"]

# Default command if no other command is provided.
# This will run after the entrypoint script finishes its pre-startup tasks.
CMD ["ollama", "serve"]