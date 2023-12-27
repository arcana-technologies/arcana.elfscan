CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(arcana)
INCLUDE_DIRECTORIES(
	/opt/elfmaster/lib
	/opt/elfmaster/include
	include
	src
	tests
)
SET(CMAKE_C_FLAGS "-Wall -g")
ADD_LIBRARY(elfmaster STATIC IMPORTED)
SET_PROPERTY(TARGET elfmaster PROPERTY IMPORTED_LOCATION /opt/elfmaster/lib/libelfmaster.a)
ADD_EXECUTABLE(arcana src/main.c src/heuristics_util.c src/heuristics_l2.c src/so.c src/obj.c src/heuristics.c src/config.c src/internal.c src/util.c src/container.c)
TARGET_LINK_LIBRARIES(arcana elfmaster dl m)



