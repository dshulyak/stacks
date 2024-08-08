# stacks

**stacks** is a bpf-based tool to collect stack traces together with resource usage.
as of now it can collect data for the following events:
- cpu profiling
- scheduler events
- changes in rss
- block io and vfs events
- tcp/udp send/recv events
  
all events can be collected with user/kernel stacks and symbolized and generally doesn't require changes in the software.
one required change might be to compile with `force-frame-pointers=yes`, and it is also beneficial to keep `debug=1`.

additionally, **tracing-stacks** is a basic extension for popular tracing crate.
if enabled it will label all os events that happened within the span with correct span and span name.
TODO add an example how it is useful (e.g in pprof or traceviewer) 

the data is collected into parquet files. it can be later exported into
pprof or chrome traceviewer with **stacksexport** tool or explored with jupyter.

i provided several examples how it can be used in [explore](./explore) directory.

## Using

To compile you need the following dependencies:

```sh
sudo apt install -y build-essential autoconf clang-15 flex bison pkg-config autopoint
sudo ln -s /usr/include/asm-generic /usr/include/asm
sudo rm -f /bin/clang
sudo ln -s /usr/bin/clang-15 /bin/clang
```

And then install with cargo:

```sh
cargo install --path stacks
cargo install --path stacksexport
```

By default tool will collect profile at 99hz, rss changes with user traces and kernel switches with kernel traces.
```sh
sudo stacks --help
```

To open pprof install [pprof tool](https://github.com/google/pprof).
```sh
stacksexport pprof --help
```

And to open trace viewer follow these [instructions](https://chromium.googlesource.com/catapult/+/refs/heads/main/tracing/README.md) .
```sh
stacksexport trace --help
```