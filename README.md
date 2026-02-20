# youtube-unthrottle

## Usage

`youtube-unthrottle` implements a small subset of tools like
[LuanRT/googlevideo](https://github.com/LuanRT/googlevideo),
[yt-dlp](https://github.com/yt-dlp/yt-dlp),
and of course, [youtube-dl](https://github.com/ytdl-org/youtube-dl).

In particular, `youtube-unthrottle` extracts the video and audio streams
from a YouTube link passed via `argv[1]`. A program like `mpv` can act on
this output like:

```sh
uri="$(xclip -o)"
youtube-unthrottle "$uri" --visitor-data ... --proof-of-origin ... &

sleep 1

# open TCP connections to youtube-unthrottle process
exec 5< /dev/tcp/localhost/20000
exec 6< /dev/tcp/localhost/20000

# pass open file descriptors to mpv for streaming playback
mpv --title="$uri" --window-scale=0.5 --audio-file=fd://5 fd://6
```

## Goals

Our main challenge: YouTube obfuscates its stream URLs and pairs them with
dynamic JavaScript-based deobfuscation logic. To get usable URLs, we must
apply the latter to the former.

Why solve this problem anew, when tools like `yt-dlp` already exist? I have
mainly learning in mind:

- embed a scripting language within another program
- use the C APIs of libcurl and pcre2, without relying on a higher-level
  language wrapper
- test-drive the [-fanalyzer](https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10) gcc option
- see whether [ASan](https://clang.llvm.org/docs/AddressSanitizer.html),
  [LSan](https://clang.llvm.org/docs/LeakSanitizer.html),
  and [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
  catch problems caused by changing server-side state
- try out sandboxing APIs like
  [libseccomp](https://man.archlinux.org/man/seccomp_rule_add.3.en),
  [Landlock](https://docs.kernel.org/userspace-api/landlock.html),
  [pledge()](https://man.openbsd.org/pledge.2),
  and [unveil()](https://man.openbsd.org/unveil.2)

I also want to watch YouTube without:

- crashing my desktop PC due to CPU/GPU thermals
- needing the OOM killer to save me from swap death
- seeing jank, tearing, and other visual glitches

I like to avoid python3 as well, which e.g. `yt-dlp` requires.

## Platforms

I've tested on Arch Linux, OpenBSD 7.6, and macOS 15.4.

## Dependencies

```
ada
cmake
curl
jansson
libseccomp
pcre2
protobuf-c
quickjs
```

Optionally, for code coverage and fuzzing:

```
clang
llvm
```

## Build

To build and run:

```sh
cmake --preset default
cmake --build --preset default
./build/youtube-unthrottle --help
```

To build and run tests:

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

To rebuild from scratch:

```sh
cmake --preset default --fresh
cmake --build --preset default --clean-first
```

To build with clang instead of gcc:

```sh
cmake --preset clang --fresh
cmake --build --preset default --clean-first
```

To create a code coverage report:

```sh
cmake --preset coverage --fresh
cmake --build --preset default --clean-first
COVERAGE_PROFILE_DIR=coverage.profraw ctest --preset default
./scripts/coverage.sh coverage.profraw ./build/coverage.xml
llvm-cov show -instr-profile=./build/coverage.profdata -object ./build/youtube-unthrottle
```

To build and fuzz:

```sh
cmake --preset fuzzer --fresh
cmake --build --preset default --clean-first
cd ./build/tests/fuzzer/
cp -pr ../../../tests/fuzzer/samples/find_js_deobfuscator corpus
./find_js_deobfuscator -max_len=3000000 corpus > fuzz.log 2>&1 &
```
