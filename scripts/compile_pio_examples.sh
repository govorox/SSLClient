#!/usr/bin/bash

# Set the root directory containing the example directories
ROOT_DIR=$(pwd)
CLEAN=false

# Environments to test
ENVIRONMENTS=(
  "esp32dev" 
  "esp32doit-devkit-v1" 
  "esp-wrover-kit" 
  "esp32dev-framework-v3" 
  "esp32doit-devkit-v1-framework-v3" 
  "esp-wrover-kit-framework-v3"
)

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

  # Check if the board environment is defined in platformio.ini
  if ! grep -q "\[env:$board\]" platformio.ini; then
    echo "Environment for board $board not defined in $example_dir/platformio.ini"
    RESULTS["$example_name,$board"]="Failed (environment not defined)"
    return 1
  fi

  # Compile the example using platformio
  pio run -e "$board"

  # Check if compilation was successful
  if [ $? -ne 0 ]; then
    echo "Compilation failed for $example_dir for board: $board" >> "$ROOT_DIR/compile_errors.log"
    RESULTS["$example_name,$board"]="Failed"
    return 1
  fi

  echo "Compilation successful for $example_dir for board: $board"
  RESULTS["$example_name,$board"]="Passed"
}

# Function to clean the example
clean_example() {
  local example_dir=$1
  echo "Cleaning example in directory: $example_dir"

  # Change to the example directory
  cd "$example_dir" || exit 1

  # Clean the example using platformio
  if [ -f "platformio.ini" ]; then
    pio run --target clean
  else
    echo "No recognized build system (platformio.ini) found in $example_dir"
    return 1
  fi

  echo "Cleaning successful for $example_dir"

  # Remove .pio directory if --clean option is passed
  if [ "$CLEAN" = true ]; then
    echo "Removing .pio directory in $example_dir"
    rm -rf .pio
  fi

  # Return to the root directory
  cd "$ROOT_DIR" || exit 1
}

# Remove previous log file
rm -f "$ROOT_DIR/compile_errors.log"

# Iterate over each example directory
for example_dir in "$ROOT_DIR"/examples/Esp32-platformIO/*/; do
  echo "$example_dir"
  # Check if the directory contains platformio.ini
  if [ -f "$example_dir/platformio.ini" ]; then
    for board in "${ENVIRONMENTS[@]}"; do
      compile_example "$example_dir" "$board"
    done

    # Clean the example after all board-specific compilations are complete
    clean_example "$example_dir"
  else
    echo "Skipping directory $example_dir (no recognized build files)"
  fi
done

# Generate summary
echo "Compilation Summary:"
echo "===================="
for key in "${!RESULTS[@]}"; do
  IFS=',' read -r example_name board <<< "$key"
  echo "Example: $example_name, Board: $board, Result: ${RESULTS[$key]}"
done

echo "All examples processed. Check compile_errors.log for any compilation errors."
