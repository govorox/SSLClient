#!/usr/bin/bash

# Set the root directory containing the example directories
ROOT_DIR=$(pwd)
CLEAN=false

# Boards to test
BOARDS=("esp32:esp32:esp32doit-devkit-v1" "esp32:esp32:esp32wroverkit")

# Parse command line options
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --clean) CLEAN=true ;;
    *) echo "Unknown parameter passed: $1"; exit 1 ;;
  esac
  shift
done

# Initialize results array
declare -A RESULTS

# Function to compile the example for a specific board
compile_example() {
  local example_dir=$1
  local board=$2
  local example_name
  example_name=$(basename "$example_dir")
  echo "Compiling example in directory: $example_dir for board: $board"

  # Change to the example directory
  cd "$example_dir" || exit 1

  # Compile the example using arduino-cli
  # arduino-cli compile --build-property "compiler.cpp.extra_flags=-E -H" --clean --fqbn "$board" . || {
  arduino-cli compile --clean --fqbn "$board" . || {
    echo "Compilation failed for $example_dir for board: $board" >> "$ROOT_DIR/compile_errors.log"
    RESULTS["$example_name,$board"]="Failed"
    return 1
  }

  echo "Compilation successful for $example_dir for board: $board"
  RESULTS["$example_name,$board"]="Passed"
}

# Function to clean the example
clean_example() {
  local example_dir=$1
  echo "Cleaning example in directory: $example_dir"

  # Change to the example directory
  cd "$example_dir" || exit 1

  # Clean the example using arduino-cli
  arduino-cli cache clean || {
    echo "Cleaning failed for $example_dir"
    return 1
  }

  echo "Cleaning successful for $example_dir"

  # Remove build directory if --clean option is passed
  if [ "$CLEAN" = true ]; then
    echo "Removing build directory in $example_dir"
    rm -rf build
  fi

  # Return to the root directory
  cd "$ROOT_DIR" || exit 1
}

# Remove previous log file
rm -f "$ROOT_DIR/compile_errors.log"

compile_example "$ROOT_DIR"/examples/Esp32-Arduino-IDE/https_gsm_SIM800/ "esp32:esp32:esp32doit-devkit-v1"

# Iterate over each example directory
# for example_dir in "$ROOT_DIR"/examples/Esp32-Arduino-IDE/*/; do
#   echo "$example_dir"
#   # Check if the directory contains a .ino file
#   if [ -f "$example_dir"/*.ino ]; then
#     for board in "${BOARDS[@]}"; do
#       compile_example "$example_dir" "$board"
#     done

#     # Clean the example after all board-specific compilations are complete
#     clean_example "$example_dir"
#   else
#     echo "Skipping directory $example_dir (no .ino file found)"
#   fi
# done

# Generate summary
echo "Compilation Summary:"
echo "===================="
for key in "${!RESULTS[@]}"; do
  IFS=',' read -r example_name board <<< "$key"
  echo "Example: $example_name, Board: $board, Result: ${RESULTS[$key]}"
done

echo "All examples processed. Check compile_errors.log for any compilation errors."
