# CyberLLM sample data

This directory contains sample log files for testing and demonstration.

- `auth.log` — sample syslog/auth log with SSH brute-force activity and a sudo command.

Use with:

    cyberllm analyze samples/auth.log --provider ollama --model llama3.2