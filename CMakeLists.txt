cmake_minimum_required(VERSION 3.19)

set(PROJECT_NAME super-thread)

project(${PROJECT_NAME} C)

#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_STANDARD 11)

set(JJCOM_HAVE_CJSON 1)
#set(JJCOM_HAVE_SOCKET 1)
set(JJCOM_HAVE_ICONV 1)
set(JJCOM_HAVE_MATH 1)
#set(JJCOM_HAVE_UUID 1)

set(WIN32_UNICODE true)
set(WIN32_LINK_SUBSYS window)
set(HAVE_CJSON true)
set(HAVE_ICONV true)

if (WIN32 AND MINGW)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -static-libgcc ")

        if (WIN32_UNICODE)
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -municode -DUNICODE -D_UNICODE ")
        endif()

        if (${WIN32_LINK_SUBSYS} STREQUAL "window")
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mwindows -DSUBSYS_WINDOW ")
        endif()

        if (${WIN32_LINK_SUBSYS} STREQUAL "console")
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mconsole ")
        endif()
endif()

set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall -Wextra ")

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g3 -ggdb3 -gdwarf-4 -O0 ")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 ")
endif()

add_subdirectory(lib/tommyds)
add_subdirectory(lib/libjj)

set(SOURCE_FILES
    src/main.c
    src/config.c
    src/config.h
    src/supervisor.c
    src/supervisor.h
    src/myntapi.h
    src/sysinfo.c
    src/sysinfo.h
    src/tray.c
    src/tray.h
    src/superthread.h
    src/superthread.c
    asset/resource.h
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

add_executable(${PROJECT_NAME} ${APPRES_OBJS})
target_sources(${PROJECT_NAME} PRIVATE ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC include/phnt/include)
target_include_directories(${PROJECT_NAME} PUBLIC lib)
target_include_directories(${PROJECT_NAME} PUBLIC asset)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})

#target_link_directories(${PROJECT_NAME} PUBLIC ${CMAKE_BINARY_DIR}/tommyds)

target_link_libraries(${PROJECT_NAME} tommyds)
target_link_libraries(${PROJECT_NAME} jjcom)
target_link_libraries(${PROJECT_NAME} iconv)
target_link_libraries(${PROJECT_NAME} ntdll)
target_link_libraries(${PROJECT_NAME} ntoskrnl)

set(INSTALL_DEST "Build-${CMAKE_BUILD_TYPE}")

install(TARGETS ${PROJECT_NAME} DESTINATION "${INSTALL_DEST}")

message(STATUS "CMake Config: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: " ${CMAKE_C_COMPILER})
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")
message(STATUS "Source Directory: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "External Object: ${APPRES_OBJS}")
message(STATUS "Install destination: " ${INSTALL_DEST})
