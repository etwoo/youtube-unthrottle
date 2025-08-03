cmake_minimum_required(VERSION 3.25)
project(youtube-unthrottle)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(AddExternalPackages)
include(AdjustGlobalIncludesAndLibraries)
include(GenerateGoogleVideoProtoC)

add_external_packages()
adjust_global_includes_and_libraries()

add_executable(youtube-unthrottle)
target_sources(youtube-unthrottle PUBLIC main.c)
target_link_libraries(youtube-unthrottle PRIVATE sanitizers)
target_link_libraries(youtube-unthrottle PRIVATE youtube)

add_library(youtube)
target_include_directories(youtube PUBLIC include)
target_link_libraries(youtube PRIVATE youtube-internals)

add_library(youtube-internals) # implementation details, mainly useful for tests
generate_googlevideo_protoc(youtube-internals)
# test-driver uses VideoStreaming__VideoPlaybackAbrRequest structure and
# associated unpack() API for testing purposes
target_include_directories(youtube-internals SYSTEM PUBLIC
	${googlevideo_BINARY_DIR}
)
# test-driver uses youtube-internals to exercise implementation APIs like
# ./src/lib/{js,re}.h and ./src/sandbox/linux/{landlock,seccomp}.h
target_include_directories(youtube-internals PUBLIC
	src
)
add_subdirectory(src)

if (BUILD_TESTING)
	include(CTest)
	add_subdirectory(tests)
endif (BUILD_TESTING)

#
# Set up a custom `fmt` target that runs clang-format.
#
# I would prefer to use the builtin cmake integration instead:
#
#     set(CMAKE_C_CPPLINT clang-format -Werror --dry-run)
#
# ... but unfortunately, this only runs clang-format on *.c files, while
# ignoring *.h files! If this cmake behavior ever changes, we could probably
# remove the following custom code and allow clang-format to run implicitly as
# part of the --build step.
#

find_program(FORMATTER clang-format)
if (NOT FORMATTER)
	# try harder on OpenBSD
	find_program(FORMATTER clang-format-16 HINTS /usr/local/bin)
endif (NOT FORMATTER)

add_custom_target(fmt COMMAND find
	${PROJECT_SOURCE_DIR}/main.c
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/src
	${PROJECT_SOURCE_DIR}/tests
	( -name *.h -or -name *.c )
	-exec ${FORMATTER} -Werror --dry-run {} +
	VERBATIM USES_TERMINAL
)

#
# Figure out which options the compiler supports, and enable them.
#

add_library(my_cflags INTERFACE)
target_link_libraries(youtube-unthrottle PRIVATE my_cflags)
target_link_libraries(youtube PRIVATE my_cflags)
target_link_libraries(youtube-internals PRIVATE my_cflags)

target_compile_features(my_cflags INTERFACE c_std_11)

target_compile_options(my_cflags INTERFACE
	-Wall
	-Wextra
	-pedantic
	-pipe
)

if (BUILD_COVERAGE)
	include(CheckCodeCoverage)
	check_code_coverage(my_cflags)
endif (BUILD_COVERAGE)

include(CheckHardened)
check_hardened(my_cflags)

include(CheckTargetCompileOptions)
check_target_compile_options(my_cflags -Wimplicit-fallthrough=5)

# Enable some of the options recommended by https://kristerw.blogspot.com
check_target_compile_options(my_cflags -Wduplicated-branches)
check_target_compile_options(my_cflags -Wduplicated-cond)
check_target_compile_options(my_cflags -Wformat=2)
check_target_compile_options(my_cflags -Wformat-signedness)
check_target_compile_options(my_cflags -Wlogical-op)
check_target_compile_options(my_cflags -Wshadow)

# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10
check_target_compile_options(my_cflags -fanalyzer)

# Enable some options copied from the Linux kernel Makefile
check_target_compile_options(my_cflags -Wmissing-prototypes)
check_target_compile_options(my_cflags -Wstrict-prototypes)

#
# Enable sanitizers, except TSan (code currently runs single-threaded)
#

add_library(sanitizers INTERFACE)

include(CheckSanitizer)
check_sanitizer(sanitizers -fsanitize=address asan CFLAG_ASAN)
if (NOT CFLAG_ASAN)
	check_sanitizer(sanitizers -fsanitize=leak lsan CFLAG_LSAN)
endif (NOT CFLAG_ASAN)
check_sanitizer(sanitizers -fsanitize=undefined ubsan CFLAG_UBSAN)

#
# Quiet warnings under clang like:
#
# warning: token pasting of ',' and __VA_ARGS__ .. a GNU extension
#
# -pedantic enables the -Wgnu-zero-variadic-macro-arguments diagnostic and
# detects (mis)use of C language features outside of this project's c_std_*
# version (including unintended GNU-isms). All that said, we accept with this
# specific GNU-ism and so suppress this particular warning.
#
# warning: -Wl,-z,relro: 'linker' input unused [-Wunused-command-line-argument]
#
# We could avoid these warnings entirely by moving these options from CFLAGS TO
# LDFLAGS, but -Wl,_ seems the most common idiom for providing linker flags (at
# least going by blog posts online). As a result, I prefer to use -Wl,_ in
# CFLAGS for ease of future googling.
#

if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	target_compile_options(my_cflags INTERFACE
		-Wno-gnu-zero-variadic-macro-arguments
		-Qunused-arguments
	)
endif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
