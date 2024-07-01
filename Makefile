TARGET := youtube-unthrottle
LDLIBS := -lcurl -lduktape -lpcre2-8

CFLAGS += -g -Wall -Wextra

# Enable pre-determined hardening options, which currently include:
#  -D_FORTIFY_SOURCE=3
#  -D_GLIBCXX_ASSERTIONS
#  -ftrivial-auto-var-init=zero
#  -fPIE -pie
#  -Wl,-z,now
#  -Wl,-z,relro
#  -fstack-protector-strong
#  -fstack-clash-protection
#  -fcf-protection=full
CFLAGS += -fhardened
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
CFLAGS += -fstrict-flex-arrays
CFLAGS += -Wtrampolines
CFLAGS += -Wimplicit-fallthrough
# too noisy: -Wconversion -Wsign-conversion
CFLAGS += -Werror=implicit
CFLAGS += -Werror=incompatible-pointer-types
CFLAGS += -Werror=int-conversion
CFLAGS += -Wl,-z,nodlopen
CFLAGS += -Wl,-z,noexecstack

# Enable some options copied from the Linux kernel Makefile:
CFLAGS += -Wmissing-prototypes -Wstrict-prototypes

# Enable ASan, LSan, and UBsan:
CFLAGS += -fsanitize=address -fsanitize=leak -fsanitize=undefined
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
HDRS := $(wildcard $(addsuffix /*.h,$(INCLUDES)))
CFLAGS += $(addprefix -I,$(INCLUDES)) -MMD -MP
CFLAGS := $(strip $(CFLAGS))

$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDLIBS) $(OBJS) -o $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:	clean
clean:
	rm -r -- $(BUILD_DIR)

.PHONY: fmt
fmt:
	clang-format -Werror --dry-run $(HDRS) $(SRCS)

.PHONY: test
test:
	$(BUILD_DIR)/$(TARGET) --help
# stub for `make test`; doesn't really do anything right now

-include $(DEPS)
