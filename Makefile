OS := $(shell uname)
TARGET := youtube-unthrottle
LDLIBS := -lcurl -lduktape -lpcre2-8

CFLAGS += -g -Wall -Wextra

CC_OPTIONS := $(shell $(CC) --help=common)
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
		  -Wl,-z,now $\
		  -Wl,-z,relro $\
		  -fstack-protector-strong $\
		  -fstack-clash-protection $\
		  -fcf-protection=full
endif
CFLAGS += -O2            # required for _FORTIFY_SOURCE to be enabled

# Enable some of the warnings recommended by https://kristerw.blogspot.com
CFLAGS += -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict $\
          -Wnull-dereference -Wshadow -Wformat -Wformat=2
# too noisy: -Wjump-misses-init

# https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc
CFLAGS += -Werror=format-security -Werror=implicit-function-declaration
CFLAGS += -fpie -Wl,-pie # note: -pie, not -pic -> executable, not library
CFLAGS += -pipe          # avoid temporary files, speeding up builds
CFLAGS += -Wl,-z,defs    # detect and reject underlinking

# https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10
CFLAGS += -fanalyzer

# https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
CFLAGS += -Wtrampolines
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
