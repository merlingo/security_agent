cmake_minimum_required(VERSION 3.10)
project(security_agent)

# C++ standartını ayarla
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(CURL REQUIRED)

# Set RabbitMQ paths manually
set(RABBITMQ_INCLUDE_DIR "/opt/homebrew/include")
set(RABBITMQ_LIBRARIES "/opt/homebrew/lib/librabbitmq.4.dylib")

# Set yaml-cpp paths manually
set(YAML_CPP_ROOT "/opt/homebrew/Cellar/yaml-cpp/0.8.0")
set(YAML_CPP_INCLUDE_DIR "${YAML_CPP_ROOT}/include")
set(YAML_CPP_LIBRARY "${YAML_CPP_ROOT}/lib/libyaml-cpp.dylib")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${RABBITMQ_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${YAML_CPP_INCLUDE_DIR}
    ${GTEST_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

# security_agent kütüphanesi
add_library(security_agent_lib STATIC
    src/modules/event_management/event_manager.cpp
    src/modules/event_management/event.cpp
    src/modules/response/response_module.cpp
    src/modules/logging/logging_module.cpp
    src/modules/routing/routing_module.cpp
    src/modules/monitoring/monitoring_interface.cpp
    src/modules/monitoring/syslog_monitoring.cpp
    src/modules/monitoring/network_monitoring.cpp
    src/modules/monitoring/process_monitoring.cpp
    src/modules/monitoring/file_monitoring.cpp
    src/modules/detection/detection_module.cpp
    src/utils/base64.cpp
)

target_link_libraries(security_agent_lib PRIVATE
    ${OPENSSL_LIBRARIES}
    ${RABBITMQ_LIBRARIES}
    ${YAML_CPP_LIBRARY}
    ${CURL_LIBRARIES}
)

# Ana uygulama
add_executable(security_agent
    src/main.cpp
)

target_link_libraries(security_agent PRIVATE
    security_agent_lib
)

# Tests
enable_testing()

# Test hedefleri
add_executable(security_agent_test
    tests/modules/event_management/event_manager_test.cpp
    tests/modules/response/response_module_test.cpp
)

target_link_libraries(security_agent_test PRIVATE
    security_agent_lib
    GTest::GTest
    GTest::Main
    GTest::gmock
    GTest::gmock_main
)

target_compile_definitions(security_agent_test PRIVATE TESTING)

# Logging modülü testi
add_executable(logging_module_test
    tests/modules/logging/logging_module_test.cpp
)

target_link_libraries(logging_module_test PRIVATE
    security_agent_lib
    GTest::GTest
    GTest::Main
    GTest::gmock
    GTest::gmock_main
)

add_test(NAME LoggingModuleTest COMMAND logging_module_test)

# Routing modülü testi
add_executable(routing_module_test
    tests/modules/routing/routing_module_test.cpp
)

target_link_libraries(routing_module_test PRIVATE
    security_agent_lib
    GTest::GTest
    GTest::Main
    GTest::gmock
    GTest::gmock_main
)

add_test(NAME RoutingModuleTest COMMAND routing_module_test)

# Syslog Monitoring modülü testi
add_executable(syslog_monitoring_test
    tests/modules/monitoring/syslog_monitoring_test.cpp
)

target_link_libraries(syslog_monitoring_test PRIVATE
    security_agent_lib
    GTest::GTest
    GTest::Main
    GTest::gmock
    GTest::gmock_main
)

add_test(NAME SyslogEntryTest COMMAND syslog_monitoring_test)

# Network Monitoring modülü testi - geçici olarak devre dışı
# add_executable(network_monitoring_test
#     tests/modules/monitoring/network_monitoring_test.cpp
# )
# 
# target_link_libraries(network_monitoring_test PRIVATE
#     security_agent_lib
#     GTest::GTest
#     GTest::Main
#     GTest::gmock
#     GTest::gmock_main
# )
# 
# add_test(NAME NetworkMonitoringTest COMMAND network_monitoring_test)

# Process Monitoring modülü testi - geçici olarak devre dışı
# add_executable(process_monitoring_test
#     tests/modules/monitoring/process_monitoring_test.cpp
# )
# 
# target_link_libraries(process_monitoring_test PRIVATE
#     security_agent_lib
#     GTest::GTest
#     GTest::Main
#     GTest::gmock
#     GTest::gmock_main
# )
# 
# add_test(NAME ProcessMonitoringTest COMMAND process_monitoring_test)

# File Monitoring modülü testi - geçici olarak devre dışı
# add_executable(file_monitoring_test
#     tests/modules/monitoring/file_monitoring_test.cpp
# )
# 
# target_link_libraries(file_monitoring_test PRIVATE
#     security_agent_lib
#     GTest::GTest
#     GTest::Main
#     GTest::gmock
#     GTest::gmock_main
# )
# 
# add_test(NAME FileMonitoringTest COMMAND file_monitoring_test) 