include_guard(GLOBAL)

include(get_cpm)
find_package(PkgConfig)

macro(generate_googlevideo_protoc target)
	CPMAddPackage(
		NAME googlevideo
		GITHUB_REPOSITORY LuanRT/googlevideo
		GIT_TAG e185cbcd88a13e2c45a5668ffa6c860bf302efee # 4.0.1
		DOWNLOAD_ONLY YES
	)

	pkg_check_modules(PROTOBUF REQUIRED libprotobuf-c)

	target_include_directories(${target} PUBLIC
		${googlevideo_BINARY_DIR}
		${PROTOBUF_INCLUDE_DIRS}
	)
	target_link_libraries(${target} PRIVATE
		${PROTOBUF_LINK_LIBRARIES}
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
