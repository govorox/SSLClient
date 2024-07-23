#!/usr/bin/bash

rm -rf ~/SSLClient
git clone https://github.com/govorox/SSLClient.git ~/SSLClient
cd ~/SSLClient
git checkout 95-release-130-fails-to-compile-on-arduino-esp32-v3
mkdir -p SSLClient
mv LICENSE library.properties src SSLClient/
zip -r SSLClient.zip SSLClient
mkdir -p ~/.arduino15
echo -e "library:\n  enable_unsafe_install: true" > ~/.arduino15/arduino-cli.yaml
arduino-cli lib install --config-file ~/.arduino15/arduino-cli.yaml --zip-path SSLClient.zip
