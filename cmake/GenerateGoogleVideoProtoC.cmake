include_guard(GLOBAL)

find_package(Protobuf REQUIRED)

macro(generate_googlevideo_protoc target)
	target_link_libraries(${target} PRIVATE
		protobuf-c
	)

	set(PROTO_PREFIX "${googlevideo_SOURCE_DIR}/protos")
	file(GLOB PROTOS "${PROTO_PREFIX}/*/*.proto")
	list(FILTER PROTOS EXCLUDE REGEX "onesie_.*\.proto")

	protobuf_generate(
		TARGET ${target}
		LANGUAGE c
		OUT_VAR PROTO_C
		PROTOC_OUT_DIR ${googlevideo_BINARY_DIR}
		PROTOS ${PROTOS}
		IMPORT_DIRS ${PROTO_PREFIX}
		GENERATE_EXTENSIONS ".pb-c.h" ".pb-c.c"
	)

	set_source_files_properties(${PROTO_C} PROPERTIES
		SKIP_LINTING ON
	)

	if (BUILD_COVERAGE)
		set(DISABLE_CODE_COVERAGE
			"-fno-profile-instr-generate -fno-coverage-mapping"
		)
		set_source_files_properties(${PROTO_C} PROPERTIES
			COMPILE_FLAGS ${DISABLE_CODE_COVERAGE}
		)
	endif (BUILD_COVERAGE)
endmacro()
