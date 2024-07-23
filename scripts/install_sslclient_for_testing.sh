#!/usr/bin/bash

# Function to print usage
print_usage() {
  echo "Usage: $0 [--branch <branch_name>]"
  echo "  --branch <branch_name>   Specify the branch to checkout (default: master)"
}

# Default branch name
BRANCH="master"

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --branch)
      if [[ -n $2 && ! $2 =~ ^- ]]; then
        BRANCH=$2
        shift
      else
        echo "Error: --branch requires a non-empty option argument."
        print_usage
        exit 1
      fi
      ;;
    *)
      echo "Unknown parameter passed: $1"
      print_usage
      exit 1
      ;;
  esac
  shift
done

# Remove previous SSLClient directory if exists
rm -rf ~/SSLClient

# Clone the repository
git clone https://github.com/govorox/SSLClient.git ~/SSLClient

# Navigate to the cloned directory
cd ~/SSLClient || { echo "Failed to change directory to ~/SSLClient"; exit 1; }

# Checkout the specified branch
git checkout "$BRANCH"

# Prepare the directory for zipping
mkdir -p SSLClient
mv LICENSE library.properties src SSLClient/
zip -r SSLClient.zip SSLClient

# Create Arduino CLI configuration directory and file if not exists
mkdir -p ~/.arduino15
echo -e "library:\n  enable_unsafe_install: true" > ~/.arduino15/arduino-cli.yaml

# Install the library using Arduino CLI
arduino-cli lib install --config-file ~/.arduino15/arduino-cli.yaml --zip-path SSLClient.zip
