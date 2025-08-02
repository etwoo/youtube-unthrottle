set(PROTO_PREFIX "${googlevideo_SOURCE_DIR}/protos")
file(GLOB PROTOS RELATIVE "${PROTO_PREFIX}"
	"${PROTO_PREFIX}/misc/*.proto"
	"${PROTO_PREFIX}/video_streaming/*.proto"
)
list(FILTER PROTOS EXCLUDE REGEX "onesie_.*\.proto")

set(PROTO_FULLPATH ${PROTOS})
list(TRANSFORM PROTO_FULLPATH PREPEND "${PROTO_PREFIX}/")

set(PROTO_C ${PROTOS})
list(TRANSFORM PROTO_C REPLACE ".proto" ".pb-c.c")
list(TRANSFORM PROTO_C PREPEND "${googlevideo_BINARY_DIR}/")

add_custom_command(
	OUTPUT
		${PROTO_C}
	COMMAND
		protoc
		--proto_path=${PROTO_PREFIX}
		--c_out=${googlevideo_BINARY_DIR}
		${PROTO_FULLPATH}
	DEPENDS
		${PROTO_FULLPATH}
)
set_source_files_properties(${PROTO_C} PROPERTIES SKIP_LINTING ON)

add_library(youtube-protocol)
target_link_libraries(youtube-protocol PRIVATE my_cflags)
target_link_libraries(youtube PRIVATE youtube-protocol)

target_sources(youtube-protocol PRIVATE
	${PROTO_C}
	debug.c
	state.c
	stream.c
	varint.c
)

target_include_directories(youtube-protocol PRIVATE
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/src
)
target_include_directories(youtube-protocol SYSTEM PRIVATE
	${googlevideo_BINARY_DIR}
	${PROTOBUF_INCLUDE_DIRS}
)
target_link_libraries(youtube-protocol PRIVATE
	${PROTOBUF_LINK_LIBRARIES}
)
if (NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	target_link_libraries(youtube-protocol PRIVATE
		resolv # for b64_pton()
	)
endif (NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
