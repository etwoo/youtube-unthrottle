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
curl
duktape
pcre2
```

I developed with the following versions of these libaries (though I am
currently assuming that many other versions would work equally well):

```sh
$ pacman -Q curl duktape pcre2
curl 8.8.0-1
duktape 2.7.0-6
pcre2 10.44-1
```

## Build

```sh
make
./build/youtube-unthrottle --help
```
