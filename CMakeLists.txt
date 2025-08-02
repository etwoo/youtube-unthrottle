cmake_minimum_required(VERSION 3.25)
project(youtube-unthrottle)

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(get_cpm)

include(AdjustGlobalIncludesAndLibraries)
adjust_global_includes_and_libraries()

add_executable(youtube-unthrottle)
target_sources(youtube-unthrottle PUBLIC main.c)
target_link_libraries(youtube-unthrottle PRIVATE my_cflags sanitizers youtube)

add_library(youtube)
target_include_directories(youtube PUBLIC include)

add_library(youtube-internals)
CPMAddPackage(
	NAME googlevideo
	GITHUB_REPOSITORY LuanRT/googlevideo
	GIT_TAG e185cbcd88a13e2c45a5668ffa6c860bf302efee # 4.0.1
	DOWNLOAD_ONLY YES
)
target_include_directories(youtube-internals PUBLIC
	${googlevideo_BINARY_DIR}
	src
)
include(GenerateGoogleVideoProtoC)
generate_googlevideo_protoc(youtube-internals)

add_subdirectory(src)

if (BUILD_TESTING)
	# Note: this use of CPMAddPackage() defines ${greatest_SOURCE_DIR}
	CPMAddPackage(
		NAME greatest
		GITHUB_REPOSITORY silentbicycle/greatest
		VERSION 1.5.0
		DOWNLOAD_ONLY YES
	)
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
target_compile_features(my_cflags INTERFACE c_std_11)

target_compile_options(my_cflags INTERFACE
	-Wall
	-Wextra
	-pedantic
	-pipe
)

if (BUILD_COVERAGE)
	CPMAddPackage(
		NAME lcov-to-cobertura-xml
		GITHUB_REPOSITORY eriwen/lcov-to-cobertura-xml
		GIT_TAG 028da3798355d0260c6c6491b39347d84ca7a02d
		DOWNLOAD_ONLY YES
	)
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

