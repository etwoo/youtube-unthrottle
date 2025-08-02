include_guard(GLOBAL)

macro(generate_googlevideo_protoc target)
	target_link_libraries(${target} PRIVATE
		protobuf-c
	)

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

	target_sources(${target} PRIVATE ${PROTO_C})
endmacro()
