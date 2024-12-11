cmake_minimum_required(VERSION 3.25)
project(youtube-unthrottle)

add_executable(youtube-unthrottle)
target_sources(youtube-unthrottle PUBLIC main.c)
target_link_libraries(youtube-unthrottle PRIVATE my_cflags sanitizers youtube)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(get_cpm)

add_subdirectory(src)

if (BUILD_TESTING)
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
# It would be nice to use the builtin cmake integration instead:
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
	${CMAKE_SOURCE_DIR}/main.c
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_SOURCE_DIR}/tests
	( -name *.h -or -name *.c )
	-exec ${FORMATTER} -Werror --dry-run {} +
	VERBATIM USES_TERMINAL
)

#
# Figure out which compiler options are supported, and enable them.
#

add_library(my_cflags INTERFACE)
target_compile_features(my_cflags INTERFACE c_std_11)

target_compile_options(my_cflags INTERFACE
	-Wall
	-Wextra
	-pedantic
	-Wno-gnu-zero-variadic-macro-arguments
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

include(MaybeTargetCompileOptions)
maybe_target_compile_options(my_cflags -Wimplicit-fallthrough=5)

#
# Enable some of the warnings recommended by https://kristerw.blogspot.com
#
# ... except -Wjump-misses-init, which is too noisy
#

target_compile_options(my_cflags INTERFACE -Wshadow -Wformat=2)

maybe_target_compile_options(my_cflags -Wduplicated-cond)
maybe_target_compile_options(my_cflags -Wduplicated-branches)
maybe_target_compile_options(my_cflags -Wlogical-op)

#
# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10
#

maybe_target_compile_options(my_cflags -fanalyzer)

#
# Enable some options copied from the Linux kernel Makefile
#

target_compile_options(my_cflags INTERFACE
	-Wmissing-prototypes
	-Wstrict-prototypes
)

#
# Enable sanitizers
#
# ... except -fsanitize=thread, since we're single-threaded (for now)
#

include(CheckSanitizer)

add_library(sanitizers INTERFACE)

check_sanitizer(sanitizers -fsanitize=address asan CFLAG_ASAN)
if (NOT CFLAG_ASAN)
	check_sanitizer(sanitizers -fsanitize=leak lsan CFLAG_LSAN)
endif (NOT CFLAG_ASAN)
check_sanitizer(sanitizers -fsanitize=undefined ubsan CFLAG_UBSAN)

#
# Quiet warnings under clang like:
#
# warning: -Wl,-z,relro: 'linker' input unused [-Wunused-command-line-argument]
#
# We could avoid these warnings entirely by moving these options from CFLAGS TO
# LDFLAGS, as the latter is only passed to CC when linking the final target
# executable. However, -Wl,_ seems to be the most common idiom for providing
# linker flags (at least going by blog posts online), so I would rather stick
# with -Wl,_ in CFLAGS for ease of future googling.
#

if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	target_compile_options(my_cflags INTERFACE -Qunused-arguments)
endif (CMAKE_C_COMPILER_ID STREQUAL "Clang")

#
# Workaround PATH, include, and library issues on OpenBSD. I must be doing
# something wrong, as it seems unlikely that all cmake-based projects fail
# to find headers and libraries installed through pkg_add.
#

if (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	message(STATUS "Making sure to use /usr/local/{include,lib} on OpenBSD")
	target_include_directories(youtube PUBLIC /usr/local/include)
	target_link_directories(youtube PUBLIC /usr/local/lib)
endif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
