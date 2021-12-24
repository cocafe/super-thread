cmake_minimum_required(VERSION 3.19 FATAL_ERROR)

project(tommyds)

# -Wpadded
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native -Wall -Wextra -Wshadow -Wuninitialized -Wcast-align -Wcast-qual -g")

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Release")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()

set(SOURCE_FILES
    tommyalloc.c
    tommyalloc.h
    tommyarray.c
    tommyarray.h
    tommyarrayof.c
    tommyarrayof.h
    tommyarrayblk.c
    tommyarrayblk.h
    tommyarrayblkof.c
    tommyarrayblkof.h
    tommy.c
    tommy.h
    tommyhash.c
    tommyhashdyn.c
    tommyhashdyn.h
    tommyhash.h
    tommyhashlin.c
    tommyhashlin.h
    tommyhashtbl.c
    tommyhashtbl.h
    tommylist.c
    tommylist.h
    tommytrie.c
    tommytrie.h
    tommytrieinp.c
    tommytrieinp.h
    tommytypes.h
    tommychain.h
    )

add_library(tommyds ${SOURCE_FILES})