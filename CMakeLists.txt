cmake_minimum_required(VERSION 3.19)

set(PROJECT_NAME super-thread)

project(${PROJECT_NAME} C)

#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_STANDARD 11)

if (WIN32 AND MINGW)
        # -mconsole: console subsystem
        # -mwindows: window subsystem
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mwindows -static ")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra ")

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -ggdb3 -gdwarf-4 -O0")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()

add_subdirectory(tommyds)

set(SOURCE_FILES
    main.c
    tray.c
    endian.h
    logging.c
    logging.h
    cJSON.c
    cJSON.h
    list.h
    config_opts.c
    config_opts.h tommy_test.c)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
include_directories(tommyds)
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_BINARY_DIR}/tommyds)
target_link_libraries(${PROJECT_NAME} tommyds)
target_link_libraries(${PROJECT_NAME} iconv)

message(STATUS "CMake Config: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: " ${CMAKE_C_COMPILER})
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "Source Directory: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "External Object: ${APPRES_OBJS}")
message(STATUS "External library: " ${GLEW_LIBRARIES} " " ${GLFW_LIBRARIES})
