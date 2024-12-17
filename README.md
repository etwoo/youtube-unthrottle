# youtube-unthrottle

## Usage

`youtube-unthrottle` implements a small subset of tools like
[yt-dlp](https://github.com/yt-dlp/yt-dlp),
[rusty_ytdl](https://github.com/Mithronn/rusty_ytdl),
and of course, [youtube-dl](https://github.com/ytdl-org/youtube-dl).

Specifically, `youtube-unthrottle` extracts the video and audio stream URLs
from a YouTube link passed via `argv[1]`. A program like `mpv` can act on
this output like:

```sh
uri="$(xclip -o)"
x="/tmp/streams.txt"
youtube-unthrottle "$uri" > "$x"

audio="$(head -1 $x)"
video="$(tail -1 $x)"
mpv --title="$uri" --audio-file="$audio" "$video"
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

I've tested on 64-bit Arch Linux and 64-bit OpenBSD 7.5.

## Dependencies

```
cmake
curl
duktape
jansson
libseccomp
pcre2
```

I developed with the following versions of these libraries (though I assume
many other versions would work as well):

```sh
$ pacman -Q cmake curl duktape jansson libseccomp pcre2
cmake 3.30.0-1
curl 8.8.0-1
duktape 2.7.0-6
jansson 2.14-4
libseccomp 2.5.5-3
pcre2 10.44-1
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
