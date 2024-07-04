cmake_minimum_required(VERSION 3.15)
project(youtube-unthrottle)

set(CMAKE_DEBUG_POSTFIX d)
set(gcc_like_cc "$<COMPILE_LANG_AND_ID:C,GNU>")
set(clang_like_cc "$<COMPILE_LANG_AND_ID:C,AppleClang,Clang>")

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

add_library(project_cflags INTERFACE)
target_compile_features(project_cflags INTERFACE c_std_99)
target_compile_options(project_cflags INTERFACE
	"$<${gcc_like_cc}:$<BUILD_INTERFACE:-Wall;-Wextra;-fanalyzer>>"
	"$<${clang_like_cc}:$<BUILD_INTERFACE:-Wall;-Wextra;-Qunused-arguments>>"
)

add_executable(youtube-unthrottle)
target_sources(youtube-unthrottle PUBLIC main.c)
set_target_properties(youtube-unthrottle PROPERTIES
	DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX}
)
target_link_libraries(youtube-unthrottle PRIVATE youtube project_cflags)

add_library(libcurl SHARED IMPORTED)
add_library(libduktape${CMAKE_DEBUG_POSTFIX} SHARED IMPORTED)
add_library(libpcre2-8 SHARED IMPORTED)
target_link_libraries(youtube-unthrottle PRIVATE
	curl
	duktape${CMAKE_DEBUG_POSTFIX} # libduktape.so vs libduktaped.so
	pcre2-8
)

add_subdirectory(src)

# TODO: use check_cxx_compiler_flag()?
# TODO: add formatter for CMakeLists.txt, like `make fmt`
