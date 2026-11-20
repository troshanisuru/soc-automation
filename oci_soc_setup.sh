#!/usr/bin/env bash
#
# oci_soc_setup.sh
# Automated Setup Script for Oracle Cloud Infrastructure (OCI) SOC Brain Instance
# (Supports Always Free VM.Standard.A1.Flex ARM64 4 OCPU / 24 GB RAM + Ollama + Llama 3.1 + OCI SDK)
#

set -euo pipefail

echo "=================================================================="
echo "  OCI SOC AGENT INSTANCE AUTOMATED SETUP (Ubuntu / Ampere A1)"
echo "=================================================================="

echo "=== 1. Updating System Packages ==="
sudo apt-get update -y
sudo apt-get install -y python3-venv python3-pip curl git jq iptables-persistent

echo "=== 2. Installing Ollama & Pulling Llama 3.1 8B Model ==="
curl -fsSL https://ollama.com/install.sh | sh

sudo systemctl enable ollama || true
sudo systemctl start ollama || true
sleep 5

echo "Pulling Llama 3.1 model..."
ollama pull llama3.1

echo "=== 3. Setting Up Python Environment with OCI SDK ==="
mkdir -p ~/soc-automation
cd ~/soc-automation

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install langchain-ollama langgraph pydantic oci python-dotenv PyYAML requests

echo "=================================================================="
echo "  OCI SOC Brain Setup Complete!"
echo "=================================================================="
