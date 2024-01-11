CMAKE_MINIMUM_REQUIRED(VERSION 2.6...3.2)
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

# compile plugins
# ADD_LIBRARY(golang-plugin SHARED plugins/golang.c)
# TARGET_LINK_LIBRARIES(golang-plugin elfmaster)

# move files from repo to configuration dir /opt/arcana
install(FILES default_config/arcana.conf DESTINATION /opt/arcana/conf)
install(TARGETS arcana DESTINATION /opt/arcana/bin)
install(TARGETS arcana DESTINATION /usr/bin/)

# Create plugins directory
install(DIRECTORY DESTINATION /opt/arcana/plugins)

# install plugins
# install(TARGETS golang-plugin DESTINATION /opt/arcana/plugins)


