cmake_minimum_required(VERSION 3.14)
project(bogons VERSION 1.4.1 LANGUAGES CXX)

add_library(bogons INTERFACE)
add_library(bogons::bogons ALIAS bogons)

target_compile_features(bogons INTERFACE cxx_std_17)

target_include_directories(bogons INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

include(GNUInstallDirs)
install(TARGETS bogons EXPORT bogonsTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

enable_testing()
add_executable(test_bogons tests/test_bogons.cpp)
target_link_libraries(test_bogons PRIVATE bogons)
add_test(NAME test_bogons COMMAND test_bogons)
