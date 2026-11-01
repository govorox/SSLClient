[![Back to README](https://img.shields.io/badge/Back_to-_README-blue?style=for-the-badge)](../README.md)

# Scripts

This directory contains scripts to help with the development of the SSLClient library.

## Table of Contents
1. [Library Installation Script](#SSLClient-Library-Installation-Script) - Automates the installation of the SSLClient library.
2. [Arduino CLI Utility Script](#Arduino-CLI-Utility-Script) - Provides a convenient way to manage Arduino libraries, platforms, and frameworks.
3. [PlatformIO CLI Utility Script](#PlatformIO-CLI-Utility-Script) - Provides a convenient way to manage libraries, platforms, and frameworks using the PlatformIO CLI.

## SSLClient Library Installation Script

This script automates the process of cloning and installing the `SSLClient` library from a specified branch of the repository. It prepares the library for use with the Arduino CLI.

### Usage

Run from the root of the repository:

`./scripts/install_sslclient_for_testing.sh` [--branch <branch_name>]

#### Parameters

`--branch <branch_name>`: (Optional) Specify the branch to checkout. Defaults to master.

### Script Overview

1. Cloning the Repository: The script clones the SSLClient repository from GitHub.
2. Branch Checkout: It checks out the specified branch (or defaults to master).
3. Library Preparation: The script prepares the library by moving necessary files and creating a zip archive.
4. Installation: Finally, the script installs the library using the Arduino CLI.

### Requirements

`git`
`bash`
`arduino-cli`

## Arduino CLI Utility Script

This script provides a convenient way to manage Arduino libraries, platforms, and frameworks using the Arduino CLI. It also allows you to switch between different versions of the ESP32-Arduino core.

### Usage

`./scripts/arduino_cli_utility.sh` - Run the script to manage libraries, platforms, frameworks, and ESP32-Arduino versions. 

### Menu Options

**List Installed Libraries:** Displays a list of all libraries currently installed.
**List Installed Platforms:** Displays a list of all platforms currently installed.
**List Installed Frameworks for Boards:** Displays a list of all available frameworks for boards.
**Switch ESP32-Arduino Version:** Prompts you to enter a specific version of the ESP32-Arduino core to install.
**Exit:** Exits the script.

### Requirements

`arduino-cli` - Ensure that arduino-cli is installed and properly configured on your system before running the script.

### Script Overview
1. Library Management: List all installed libraries.
2. Platform Management: List all installed platforms.
3. Framework Management: List all available frameworks for boards.
4. ESP32 Version Management: Switch to a specific version of the ESP32-Arduino core.

## PlatformIO CLI Utility Script

This script provides a convenient way to manage libraries, platforms, and frameworks using the PlatformIO CLI. It also allows you to switch between different versions of the Arduino-ESP32 core.

### Usage

`./scripts/platformio_cli_utility.sh` - Run the script to manage libraries, platforms, frameworks, and Arduino-ESP32 versions.

### Menu Options

**List Installed Libraries:** Displays a list of all libraries currently installed.
**List Installed Platforms:** Displays a list of all platforms currently installed.
**List Installed Frameworks for Boards:** Displays a list of all available frameworks for boards that use the Arduino framework.
**Switch Arduino-ESP32 Version:** Prompts you to enter a specific version of the Arduino-ESP32 core to install.
**Exit:** Exits the script.

### Requirements

`bash`
`platformio-cli` (pio)

### Script Overview

1. Library Management: List all installed libraries using PlatformIO.
2. Platform Management: List all installed platforms using PlatformIO.
3. Framework Management: List all available frameworks for boards that support the Arduino framework using PlatformIO.
4. Arduino-ESP32 Version Management: Switch to a specific version of the Arduino-ESP32 core using PlatformIO.
