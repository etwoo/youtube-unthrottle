# TODO: isolate all protobuf code to src/lib/protobuf.{h,c} and move all of this cmake boilerplate into src/lib/CMakeLists.txt, thereby avoiding a new top-level project directory `protos`; adjust use of CMAKE_CURRENT_BINARY_DIR and target_include_directories() accordingly

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
)

add_library(youtube-protobufs)
target_sources(youtube-protobufs PRIVATE
	${PROTO_C}
)
target_include_directories(youtube-protobufs PUBLIC
	${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(youtube-protobufs PRIVATE
	protobuf-c
)
