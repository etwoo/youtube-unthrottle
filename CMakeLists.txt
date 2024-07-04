cmake_minimum_required(VERSION 3.15)
project(youtube-unthrottle)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
set(CMAKE_DEBUG_POSTFIX d)
set(gcc_like_cc "$<COMPILE_LANG_AND_ID:C,GNU>")
set(clang_like_cc "$<COMPILE_LANG_AND_ID:C,AppleClang,Clang>")

# TODO: ifeq ($(OS),OpenBSD)
# 	INCLUDES += /usr/local/include
# 	LDFLAGS += -L/usr/local/lib
# endif

add_library(my_cflags INTERFACE)
target_compile_features(my_cflags INTERFACE c_std_99)

add_executable(youtube-unthrottle)
target_sources(youtube-unthrottle PUBLIC main.c)
target_link_libraries(youtube-unthrottle PRIVATE youtube my_cflags)

add_library(libcurl SHARED IMPORTED)
add_library(libduktape${CMAKE_DEBUG_POSTFIX} SHARED IMPORTED)
add_library(libpcre2-8 SHARED IMPORTED)
target_link_libraries(youtube-unthrottle PRIVATE
	curl
	duktape${CMAKE_DEBUG_POSTFIX} # libduktape.so vs libduktaped.so
	pcre2-8
)

add_subdirectory(src)

include(CTest)
if (BUILD_TESTING)
	add_test(NAME cli-help COMMAND youtube-unthrottle --help)
	add_test(NAME cli-try-sandbox COMMAND youtube-unthrottle --try-sandbox)
endif (BUILD_TESTING)

#
# TODO: add clang-format target to CMakeLists.txt, like `make fmt`
#

#
# Figure out which compiler options are supported, and enable them.
#

include(CheckCCompilerFlag)

target_compile_options(my_cflags INTERFACE -Wall -Wextra)
# TODO: -Qunused-arguments for spurious clang linker warnings

check_c_compiler_flag(-fhardened CFLAG_HARDENED)
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

#
# Enable some of the warnings recommended by https://kristerw.blogspot.com
#
# ... except -Wjump-misses-init, which is too noisy
#

target_compile_options(my_cflags INTERFACE -Wnull-dereference -Wshadow -Wformat)
if (NOT clang_like_cc)
	# Avoid -Wformat=2 under clang, which doesn't seem to recognize when a
	# function passes a format string plus va_list to vprintf, resulting in
	# a spurious warning about the former not being a format string.
	target_compile_options(my_cflags INTERFACE -Wformat=2)
endif (NOT clang_like_cc)

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

check_c_compiler_flag(-Wrestrict CFLAG_RESTRICT)
if (CFLAG_RESTRICT)
	target_compile_options(my_cflags INTERFACE -Wrestrict)
endif (CFLAG_RESTRICT)

#
# https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc
#

target_compile_options(my_cflags INTERFACE
	-Werror=format-security
	-Werror=implicit-function-declaration
	-pipe
	-Wl,-z,defs
)

#
# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10
#

check_c_compiler_flag(-fanalyzer CFLAG_ANALYZER)
if (CFLAG_ANALYZER)
	target_compile_options(my_cflags INTERFACE -fanalyzer)
endif (CFLAG_ANALYZER)

#
# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
#
# ... except -Wconversion and -Wsign-conversion, which are too noisy
# ... and -Wl,-z,nodlopen, which causes an ld.so error on OpenBSD
#

check_c_compiler_flag(-Wtrampolines CFLAG_TRAMPOLINES)
if (CFLAG_TRAMPOLINES)
	target_compile_options(my_cflags INTERFACE -Wtrampolines)
endif (CFLAG_TRAMPOLINES)

target_compile_options(my_cflags INTERFACE
	-Wimplicit-fallthrough
	-Werror=implicit
	-Werror=incompatible-pointer-types
	-Werror=int-conversion
	-Wl,-z,noexecstack
)

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

check_c_compiler_flag(-fsanitize=address CFLAG_ASAN)
if (CFLAG_ASAN)
	target_compile_options(my_cflags INTERFACE -fsanitize=address)
endif (CFLAG_ASAN)

check_c_compiler_flag(-fsanitize=leak CFLAG_LSAN)
if (CFLAG_LSAN)
	target_compile_options(my_cflags INTERFACE -fsanitize=leak)
endif (CFLAG_LSAN)

check_c_compiler_flag(-fsanitize=undefined CFLAG_UBSAN)
if (CFLAG_UBSAN)
	target_compile_options(my_cflags INTERFACE -fsanitize=undefined)
	add_library(libubsan SHARED IMPORTED)
	target_link_libraries(my_cflags INTERFACE ubsan)
endif (CFLAG_UBSAN)
