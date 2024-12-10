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

	check_code_coverage(CFLAG_COVERAGE)
	if (NOT CFLAG_COVERAGE)
		message(FATAL_ERROR "Cannot enable code coverage")
	endif (NOT CFLAG_COVERAGE)

	target_compile_definitions(my_cflags INTERFACE WITH_COVERAGE)
	target_compile_options(my_cflags INTERFACE ${CFLAG_COVERAGE})
	target_link_options(my_cflags INTERFACE ${CFLAG_COVERAGE})
endif (BUILD_COVERAGE)

include(CheckHardened)

check_hardened(CFLAG_HARDENED -fhardened -O2)
if (CFLAG_HARDENED)
	target_compile_options(my_cflags INTERFACE -fhardened)
else (CFLAG_HARDENED)
	# -fhardened is not supported; set constituent options individually
	target_compile_options(my_cflags INTERFACE
		-D_FORTIFY_SOURCE=3
		-D_GLIBCXX_ASSERTIONS
		-fPIE -pie
		-Wl,-z,now
		-Wl,-z,relro
		-fstack-protector-strong
		-fstack-clash-protection
		-fcf-protection=full
	)
endif (CFLAG_HARDENED)

target_compile_options(my_cflags INTERFACE -O2) # req'ed by _FORTIFY_SOURCE

include(CheckCCompilerFlag)

check_c_compiler_flag(-Wimplicit-fallthrough=5 CFLAG_FALLTHROUGH_STRICT)
if (CFLAG_FALLTHROUGH_STRICT)
	target_compile_options(my_cflags INTERFACE -Wimplicit-fallthrough=5)
endif (CFLAG_FALLTHROUGH_STRICT)

#
# Enable some of the warnings recommended by https://kristerw.blogspot.com
#
# ... except -Wjump-misses-init, which is too noisy
#

target_compile_options(my_cflags INTERFACE -Wshadow -Wformat=2)

check_c_compiler_flag(-Wduplicated-cond CFLAG_DUPLICATED_COND)
if (CFLAG_DUPLICATED_COND)
	target_compile_options(my_cflags INTERFACE -Wduplicated-cond)
endif (CFLAG_DUPLICATED_COND)

check_c_compiler_flag(-Wduplicated-branches CFLAG_DUPLICATED_BRANCHES)
if (CFLAG_DUPLICATED_BRANCHES)
	target_compile_options(my_cflags INTERFACE -Wduplicated-branches)
endif (CFLAG_DUPLICATED_BRANCHES)

check_c_compiler_flag(-Wlogical-op CFLAG_LOGICAL_OP)
if (CFLAG_LOGICAL_OP)
	target_compile_options(my_cflags INTERFACE -Wlogical-op)
endif (CFLAG_LOGICAL_OP)

#
# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10
#

check_c_compiler_flag(-fanalyzer CFLAG_ANALYZER)
if (CFLAG_ANALYZER)
	target_compile_options(my_cflags INTERFACE -fanalyzer)
endif (CFLAG_ANALYZER)

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

check_sanitizer(CFLAG_ASAN -fsanitize=address asan)
if (CFLAG_ASAN)
	target_compile_options(sanitizers INTERFACE -fsanitize=address)
	add_library(libasan SHARED IMPORTED)
	target_link_libraries(sanitizers INTERFACE asan)
endif (CFLAG_ASAN)

check_sanitizer(CFLAG_LSAN -fsanitize=leak lsan)
if (CFLAG_LSAN)
	if (CFLAG_ASAN)
		message(STATUS "LSan stand-alone mode is unnecessary because ASan is already enabled")
	else (CFLAG_ASAN)
		target_compile_options(sanitizers INTERFACE -fsanitize=leak)
		add_library(liblsan SHARED IMPORTED)
		target_link_libraries(sanitizers INTERFACE lsan)
	endif (CFLAG_ASAN)
endif (CFLAG_LSAN)

check_sanitizer(CFLAG_UBSAN -fsanitize=undefined ubsan)
if (CFLAG_UBSAN)
	target_compile_options(sanitizers INTERFACE -fsanitize=undefined)
	add_library(libubsan SHARED IMPORTED)
	target_link_libraries(sanitizers INTERFACE ubsan)
endif (CFLAG_UBSAN)

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
