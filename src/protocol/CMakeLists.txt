CPMAddPackage(
	NAME googlevideo
	GITHUB_REPOSITORY LuanRT/googlevideo
	GIT_TAG e217d50236486025e8813ed88ec16d15a7a60c89 # 3.0.0
	DOWNLOAD_ONLY YES
)

set(PROTO_PREFIX "${googlevideo_SOURCE_DIR}/protos")
file(GLOB PROTOS RELATIVE "${PROTO_PREFIX}"
	"${PROTO_PREFIX}/misc/*.proto"
	"${PROTO_PREFIX}/video_streaming/*.proto"
)

set(PROTO_FULLPATH ${PROTOS})
list(TRANSFORM PROTO_FULLPATH PREPEND "${PROTO_PREFIX}/")

set(PROTO_C ${PROTOS})
list(TRANSFORM PROTO_C REPLACE ".proto" ".pb-c.c")
list(TRANSFORM PROTO_C PREPEND "${CMAKE_CURRENT_BINARY_DIR}/")

add_custom_command(
	OUTPUT
		${PROTO_C}
	COMMAND
		protoc-c
		--proto_path="${PROTO_PREFIX}"
		--c_out=.
		${PROTO_FULLPATH}
	DEPENDS
		${PROTO_FULLPATH}
)

add_library(youtube-protocol)

target_sources(youtube-protocol PRIVATE
	${PROTO_C}
	stream.c
)
target_include_directories(youtube-protocol PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(youtube-protocol PRIVATE
	my_cflags
	protobuf-c
)
if (NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	target_link_libraries(youtube-protocol PRIVATE
		resolv # for b64_pton()
	)
endif (NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")

target_link_libraries(youtube PRIVATE youtube-protocol)
