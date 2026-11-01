"""Compile and run isolated logging checks with a host C++ compiler."""

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#include "log_.h"

int main() {
  int evaluated = 0;
  SSL_CLIENT_LOG_E("%d", ++evaluated);
  SSL_CLIENT_LOG_W("%d", ++evaluated);
  SSL_CLIENT_LOG_I("%d", ++evaluated);
  SSL_CLIENT_LOG_D("%d", ++evaluated);
  SSL_CLIENT_LOG_V("%d", ++evaluated);
  if (evaluated != EXPECTED || calls != EXPECTED) return 1;

  // Suppressing library logs must not suppress application debug logs.
  log_d("application %d", ++evaluated);
  if (evaluated != EXPECTED + 1 || calls != EXPECTED + 1) return 2;

  // Wrappers must remain safe within an unbraced if/else.
  if (false) SSL_CLIENT_LOG_E("unused");
  else ++evaluated;
  return evaluated == EXPECTED + 2 ? 0 : 3;
}
'''
ARDUINO = r'''
#pragma once
static int calls = 0;
template <typename... Args> void platform_log(const char*, Args...) { ++calls; }
#define log_e(...) platform_log(__VA_ARGS__)
#define log_w(...) platform_log(__VA_ARGS__)
#define log_i(...) platform_log(__VA_ARGS__)
#define log_d(...) platform_log(__VA_ARGS__)
#define log_v(...) platform_log(__VA_ARGS__)
'''


def main():
    with tempfile.TemporaryDirectory(prefix="sslclient-logging-") as temporary:
        directory = Path(temporary)
        (directory / "Arduino.h").write_text(ARDUINO)
        source = directory / "logging.cpp"
        source.write_text(SOURCE)
        for level in (None, 0, 1, 2, 3, 4, 5):
            executable = directory / ("logging.exe" if os.name == "nt" else "logging")
            command = [os.environ.get("CXX", "g++"), "-std=c++17", "-Wall", "-Wextra",
                       "-Werror", "-I", str(directory), "-I", str(ROOT / "src"),
                       f"-DEXPECTED={5 if level is None else level}"]
            if level is not None:
                command.append(f"-DSSL_CLIENT_LOG_LEVEL={level}")
            subprocess.run(command + [str(source), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)
            print(f"Logging level {level if level is not None else 'default'}: passed", flush=True)


if __name__ == "__main__":
    main()
