cmake_minimum_required(VERSION 3.19)

set(PROJECT_NAME super-thread)

project(${PROJECT_NAME} C)

#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_STANDARD 11)

set(WIN32_UNICODE true)

if (WIN32 AND MINGW)
        # -mconsole: console subsystem
        # -mwindows: window subsystem
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mwindows -static ")

        if (WIN32_UNICODE)
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -municode -DUNICODE -D_UNICODE ")
        endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra ")

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -ggdb3 -gdwarf-4 -O0")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()

add_subdirectory(tommyds)

set(SOURCE_FILES
    src/main.c
    src/endian.h
    src/logging.c
    src/logging.h
    src/cJSON.c
    src/cJSON.h
    src/list.h
    src/config_opts.c
    src/config_opts.h
    src/jkey.c
    src/jkey.h
    src/config.c
    src/config.h
    src/utils.c
    src/utils.h
    src/supervisor.c
    src/supervisor.h
    src/myntapi.h
    src/sysinfo.c
    src/sysinfo.h
    )

set(APPRES_OBJS)
if (WIN32 AND MINGW)
        set(WINRES_OUT ${CMAKE_BINARY_DIR}/appres.o)

        add_custom_command(
                OUTPUT ${WINRES_OUT}
                COMMAND windres ${CMAKE_SOURCE_DIR}/asset/app.rc ${WINRES_OUT}
        )

        add_custom_target(WinResObj ALL DEPENDS ${WINRES_OUT})

        set(APPRES_OBJS ${WINRES_OUT})
endif()

add_executable(${PROJECT_NAME} ${SOURCE_FILES} ${APPRES_OBJS})
include_directories(tommyds)
target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_BINARY_DIR}/tommyds)
target_link_libraries(${PROJECT_NAME} tommyds)
target_link_libraries(${PROJECT_NAME} iconv)
target_link_libraries(${PROJECT_NAME} ntdll)
target_link_libraries(${PROJECT_NAME} ntoskrnl)

message(STATUS "CMake Config: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: " ${CMAKE_C_COMPILER})
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "Source Directory: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "External Object: ${APPRES_OBJS}")
message(STATUS "External library: " ${GLEW_LIBRARIES} " " ${GLFW_LIBRARIES})
