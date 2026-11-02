cmake_minimum_required(VERSION 3.16)

# Use this checkout rather than downloading a registry release of SSLClient.
list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../..")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(sslclient_component_smoke)
