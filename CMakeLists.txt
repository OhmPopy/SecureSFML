cmake_minimum_required (VERSION 2.6)
project (SecureSFML)

SET(CMAKE_BUILD_TYPE Debug)

add_subdirectory (src)

include_directories(include)

add_executable (Server examples/server.cpp)
add_executable (Client examples/client.cpp)

target_link_libraries (Server sfml-network-secure) 
target_link_libraries (Client sfml-network-secure)

install(DIRECTORY include
        DESTINATION .)
