OS := $(shell uname)
TARGET := youtube-unthrottle
LDLIBS := -lcurl -lduktape -lpcre2-8

# TODO: conditional logic for gcc vs clang is yucky; would be cleaner to use CMake and then test for whether these options in an idiomatic way, rather than having this kind of conditional logic implemented in this Makefile :(
CC_TYPE := unknown
CC_VERSION := $(shell $(CC) --version)
ifneq (,$(findstring GCC,$(CC_VERSION)))
	CC_TYPE := gcc
else ifneq (,$(findstring clang,$(CC_VERSION)))
	CC_TYPE := clang
endif

ifeq ($(CC_TYPE),clang)
	# Quiet warnings about -Wl,_ options intended for the linker, which we
	# pass even to CC invocations that only compile a *.c into a *.o
	# (i.e. without acutally linking anything). We could avoid these
	# warnings entirely by moving these options from CFLAGS TO LDFLAGS, as
	# the latter is only passed to CC when linking the final TARGET binary.
	# However, -Wl,_ seems to be the most common idiom for providing linker
	# flags (at least going by blog posts online), so I would rather stick
	# with -Wl,_ in CFLAGS for ease of future googling.
	CFLAGS += -Qunused-arguments
endif

CFLAGS += -g -Wall -Wextra

CC_OPTIONS :=
ifeq ($(CC_TYPE),gcc)
	CC_OPTIONS := $(shell $(CC) --help=common)
endif

ifneq (,$(findstring -fhardened,$(CC_OPTIONS)))
	CFLAGS += -fhardened
	# Note: pre-determined hardening options currently include:
	#  -D_FORTIFY_SOURCE=3
	#  -D_GLIBCXX_ASSERTIONS
	#  -ftrivial-auto-var-init=zero
	#  -fPIE -pie
	#  -Wl,-z,now
	#  -Wl,-z,relro
	#  -fstack-protector-strong
	#  -fstack-clash-protection
	#  -fcf-protection=full
else
	# -fhardened is not supported; set constituent options individually
	CFLAGS += -D_FORTIFY_SOURCE=3 $\
		  -D_GLIBCXX_ASSERTIONS $\
		  -fPIE -pie $\
		  -Wl,-z,now $\
		  -Wl,-z,relro $\
		  -fstack-protector-strong $\
		  -fstack-clash-protection $\
		  -fcf-protection=full
endif
CFLAGS += -O2            # required for _FORTIFY_SOURCE to be enabled

# Enable some of the warnings recommended by https://kristerw.blogspot.com
ifeq ($(CC_TYPE),gcc)
	CFLAGS += -Wduplicated-cond $\
		  -Wduplicated-branches $\
		  -Wlogical-op $\
		  -Wrestrict
endif
CFLAGS += -Wnull-dereference -Wshadow -Wformat
ifeq ($(CC_TYPE),gcc)
	CFLAGS += -Wformat=2
endif
# too noisy: -Wjump-misses-init

# https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc
CFLAGS += -Werror=format-security -Werror=implicit-function-declaration
CFLAGS += -pipe          # avoid temporary files, speeding up builds
CFLAGS += -Wl,-z,defs    # detect and reject underlinking

# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10
ifeq ($(CC_TYPE),gcc)
	CFLAGS += -fanalyzer
endif

# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
ifeq ($(CC_TYPE),gcc)
	CFLAGS += -Wtrampolines
endif
CFLAGS += -Wimplicit-fallthrough
# too noisy: -Wconversion -Wsign-conversion
CFLAGS += -Werror=implicit
CFLAGS += -Werror=incompatible-pointer-types
CFLAGS += -Werror=int-conversion
# causes ld.so error on OpenBSD libc: -Wl,-z,nodlopen
CFLAGS += -Wl,-z,noexecstack

# Enable some options copied from the Linux kernel Makefile:
CFLAGS += -Wmissing-prototypes -Wstrict-prototypes

# Enable ASan, LSan, and UBsan (except on OpenBSD):
ifneq ($(OS),OpenBSD)
	CFLAGS += -fsanitize=address -fsanitize=leak -fsanitize=undefined
endif
# unnecessary for now, since we're single-threaded: -fsanitize=thread

#
# Makefile magic based on https://makefiletutorial.com/#makefile-cookbook
#
# If this gets more complicated, it might be better just to switch to CMake.
#

BUILD_DIR := ./build
SRC_DIR := ./src
SRCS := $(wildcard $(SRC_DIR)/*.c main.c)
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INCLUDES := $(SRC_DIR) ./include
ifeq ($(OS),OpenBSD)
	INCLUDES += /usr/local/include
	LDFLAGS += -L/usr/local/lib
endif
HDRS := $(wildcard $(addsuffix /*.h,$(INCLUDES)))
CFLAGS += $(addprefix -I,$(INCLUDES)) -MMD -MP

CFLAGS := $(strip $(CFLAGS))

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LDLIBS) $(OBJS) -o $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:	clean
clean:
	rm -rf -- $(BUILD_DIR)

.PHONY: fmt
fmt:
	clang-format -Werror --dry-run $(HDRS) $(SRCS)

.PHONY: test
test:
	$(BUILD_DIR)/$(TARGET) --help
# stub for `make test`; doesn't really do anything right now

-include $(DEPS)
