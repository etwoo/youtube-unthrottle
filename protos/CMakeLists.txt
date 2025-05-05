add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/client_abr_state.pb-c.h
		${CMAKE_CURRENT_BINARY_DIR}/client_abr_state.pb-c.c
	COMMAND
		protoc
		--proto_path=${CMAKE_CURRENT_SOURCE_DIR}
		--c_out=${CMAKE_CURRENT_BINARY_DIR}
		google/protobuf/any.proto
		client_abr_state.proto
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/client_abr_state.proto
)

add_library(youtube-protobufs)
target_sources(youtube-protobufs PRIVATE client_abr_state.pb-c.c)
