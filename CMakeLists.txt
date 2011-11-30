cmake_minimum_required (VERSION 2.6)
project (SecureSFML)

SET(CMAKE_BUILD_TYPE Release)

add_subdirectory (src)

include_directories(include)

add_executable (Server examples/server.cpp)
add_executable (Client examples/client.cpp)

target_link_libraries (Server secure-sfml) 
target_link_libraries (Client secure-sfml)

install(DIRECTORY include
        DESTINATION .)
