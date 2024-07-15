#!/usr/bin/bash

# Remove existing SSLClient directory to avoid conflicts
rm -rf ~/SSLClient

# Clone the repository
git clone https://github.com/govorox/SSLClient.git ~/SSLClient
cd ~/SSLClient

# Checkout the desired branch
git checkout v1.3.0  # Use the correct branch name if different

# Ensure correct structure
mkdir -p SSLClient  # Create the directory for the library files
mv LICENSE README.md docs examples library.json library.properties platformio.ini src test SSLClient/

# Compress the directory
zip -r SSLClient.zip SSLClient

# Enable unsafe installs in Arduino CLI configuration
mkdir -p ~/.arduino15
echo -e "library:\n  enable_unsafe_install: true" > ~/.arduino15/arduino-cli.yaml

# Install the library using Arduino CLI
arduino-cli lib install --config-file ~/.arduino15/arduino-cli.yaml --zip-path SSLClient.zip
