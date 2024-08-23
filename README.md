# youtube-unthrottle

## Usage

`youtube-unthrottle` is essentially a tiny subset of the functionality
provided by more sophisticated tools like
[yt-dlp](https://github.com/yt-dlp/yt-dlp),
[rusty_ytdl](https://github.com/Mithronn/rusty_ytdl).
and of course, [youtube-dl](https://github.com/ytdl-org/youtube-dl).

Specifically, `youtube-unthrottle` extracts the video and audio stream URLs
from a YouTube link passed via `argv[1]` and then prints the results to stdout.
This output can be combined with an external video player like `mpv`:

```sh
uri="$(xclip -o)"
x="/tmp/streams.txt"
youtube-unthrottle "$uri" > "$x"

audio="$(head -1 $x)"
video="$(tail -1 $x)"
mpv --title="$uri" --audio-file="$audio" "$video"
```

## Motivation

The main challenge here is that YouTube stream URLs contain parameters
that must be deobfuscated using JavaScript fragments supplied elsewhere
in the YouTube payload. This is why solving this puzzle requires the use
of an embedded JavaScript engine (in this case,
[Duktape](https://duktape.org/)).

That being said, why does this project exist, when tools like `yt-dlp`
already solve this problem (and many others) so completely? The reasons
are mainly personal for the author:

- gain experience embedding a scripting language within another program
- use the C APIs of libcurl and pcre2 directly, rather than indirectly through
  a higher-level language's wrapper
- test-drive the [-fanalyzer](https://developers.redhat.com/blog/2020/03/26/static-analysis-in-gcc-10) compiler option
- learn how [ASan](https://clang.llvm.org/docs/AddressSanitizer.html),
  [LSan](https://clang.llvm.org/docs/LeakSanitizer.html),
  and [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
  behave in the context of a greenfield codebase, especially one where
  error-handling codepaths are exercised by evolving external inputs on
  an ongoing basis
- experiment with sandboxing APIs like
  [libseccomp](https://man.archlinux.org/man/seccomp_rule_add.3.en),
  [Landlock](https://docs.kernel.org/userspace-api/landlock.html),
  [pledge()](https://man.openbsd.org/pledge.2),
  and [unveil()](https://man.openbsd.org/unveil.2)

Additional day-to-day reasons:

- watch YouTube without crashing my desktop PC due to CPU/GPU thermals
- watch YouTube without triggering the OOM killer
- watch YouTube without jank, tearing, and other visual artifacts

I also like to avoid python3 dependencies on my desktop PC whenever possible,
more for fun than anything else.

## Platforms

I've only tested this on 64-bit Arch Linux so far.

## Dependencies

```
cmake
curl
duktape
libseccomp
pcre2
```

I developed with the following versions of these libaries (though I am
currently assuming that many other versions would work equally well):

```sh
$ pacman -Q cmake curl duktape pcre2
cmake 3.30.0-1
curl 8.8.0-1
duktape 2.7.0-6
libseccomp 2.5.5-3
pcre2 10.44-1
```

Optional dependencies for code coverage and fuzzing:

```sh
clang
llvm
```

## Build

To perform an initial build:

```sh
cmake -Wdev -Werror=dev -DCMAKE_BUILD_TYPE=Debug . -B ./build
cmake --build ./build
./build/youtube-unthrottle --help
```

To rebuild from scratch, discarding any existing on-disk state:

```sh
cmake --fresh -Wdev -Werror=dev -DCMAKE_BUILD_TYPE=Debug . -B ./build
cmake --build ./build --clean-first
```

To build and run unit tests:

```sh
cmake --fresh -Wdev -Werror=dev -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=1 . -B ./build
cmake --build ./build --clean-first
ctest --test-dir ./build/tests/
```

To reconfigure and build with clang instead of gcc:

```sh
CC=clang CXX=clang++ cmake --fresh -Wdev -Werror=dev -DCMAKE_BUILD_TYPE=Debug . -B ./build
cmake --build ./build --clean-first
```

To generate a code coverage report:

```sh
CC=clang CXX=clang++ cmake --fresh -Wdev -Werror=dev -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=1 -DBUILD_COVERAGE=1 . -B ./build
cmake --build ./build --clean-first
COVERAGE_PROFILE_DIR=coverage.profraw ctest --test-dir ./build/tests/
./scripts/coverage.sh coverage.profraw coverage.xml
llvm-cov show -instr-profile=coverage.profdata -object ./build/youtube-unthrottle
```

To build and fuzz:

```sh
CC=clang CXX=clang++ cmake --fresh -Wdev -Werror=dev -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=1 . -B ./build
cmake --build ./build --clean-first
cd ./build/tests/fuzzer/
cp -pr ../../../tests/fuzzer/samples/find_js_deobfuscator corpus
./find_js_deobfuscator -max_len=3000000 corpus > fuzz.log 2>&1 &
```
