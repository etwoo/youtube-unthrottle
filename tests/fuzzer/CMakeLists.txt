macro(add_fuzzer target)
	add_executable(${target})
	target_sources(${target} PRIVATE ${target}.c)
	target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/src)
	target_link_libraries(${target} PRIVATE youtube)
	target_compile_options(${target} PRIVATE -g -O1 -fsanitize=fuzzer)
	target_link_options(${target} PRIVATE -fsanitize=fuzzer)
endmacro()

include(CheckSanitizer)

# Any sanitizer seems to bring in the fuzzer symbols required to link and
# thereby make check_c_compiler_flag() work as expected. Just use libasan.
check_sanitizer(CFLAG_FUZZER -fsanitize=fuzzer asan)
if (CFLAG_FUZZER)
	target_compile_options(my_cflags INTERFACE -fsanitize=fuzzer)
	add_fuzzer(parse_json)
	add_fuzzer(find_js_deobfuscator)
	add_fuzzer(call_js_foreach)
endif (CFLAG_FUZZER)
