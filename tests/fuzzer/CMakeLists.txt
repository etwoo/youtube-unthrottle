macro(add_fuzzer target)
	add_executable(${target})
	target_sources(${target} PRIVATE ${target}.c)
	target_include_directories(${target} PRIVATE
		${PROJECT_SOURCE_DIR}/tests # for coverage.h, test_macros.h, etc
	)
	target_link_libraries(${target} PRIVATE my_cflags youtube youtube-internals)
	target_compile_options(${target} PRIVATE -g -O1 -fsanitize=fuzzer)
	target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endmacro()

add_fuzzer(parse_json)
add_fuzzer(find_js_deobfuscator)
add_fuzzer(call_js_foreach)
