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

For example i will collect stacks from running stacks, code and firefox commands. The command below will be doing
collecting user stacks at 99hz rate, user stacks every 29th rss growth event, kernel and user stack for cpu switch event
and user/kernel stacks for write/read from block device. 

```sh
sudo ./target/release-debug/stacks stacks code firefox -p profile:u:99,rss:u:29,switch:uk,block:uk
```

After collecting data it can be viewed with stacksexport, also make to install [pprof](https://github.com/google/pprof).

### profile

```sh
stacksexport pprof -b ./target/release-debug/stacks ./stacksexport/sql/pprof/cpu_ustacks_for_buildid.sql
```

![Profile Stacks](./_assets/profile_stacks.png "Profile Stacks Image")

By providing `-b ./target/release-debug/stacks` to stacksexport it is also possible to extend collected data
with source code information for nicer UX.

![Code](./_assets/code_stacks.png)

### rss

```sh
stacksexport pprof -b ./target/release-debug/stacks ./stacksexport/sql/pprof/rss_ustacks_growth_for_buildid.sql
```

One important detail about rss is that events will be captured when program request memory pages from os,
so for example it will show rss growth when vector is initialized, but will show when element is written.

![Rss stacks](./_assets/rss_stacks.png)

### offcpu

```sh
stacksexport pprof -b ./target/release-debug/stacks ./stacksexport/sql/pprof/offcpu_stacks_for_buildid.sql
```

Offcpu events capture last stack traces before thread was switched off by scheduler,
in this profile program waits for ring buffer events in epoll.

![Offcpu stacks](./_assets/offcpu_stacks.png)

### block

There are two different profiles for block operations, by amount and duration.
And it is possible to generate different profiles for blk_read and blk_write (see queries).

```sh
stacksexport pprof -b ./target/debug/examples/writer ./stacksexport/sql/pprof/blk_ustack_duration_for_buildid.sql
stacksexport pprof -b ./target/release-debug/stacks ./stacksexport/sql/pprof/blk_ustack_amount_for_buildid.sql
```

This is not a particularly interesting example, capture from e2e/examples/writer with fsync after each write.

![Block stacks](./_assets/block_writer.png)

## Tips

### Splitting large profiles for faster pprof generation.

Query in the exporter can be updated to include timestamp:

```sql
where
    kind = 'rss'
    and buildid = decode('?buildid', 'hex')
    and timestamp < 1726573942947884522
```

Profiles are collected in relatively small batches, as at the time this is a unit of paralelizatin in datafusion.
They can be registered individually:

```sh
stacksexport pprof -b ../go-spacemesh/build/go-spacemesh ./stacksexport/sql/pprof/rss_ustacks_growth_for_buildid.sql -r "/tmp/stacks/10/STACKS-1-*"
```

### Debugging async runtime

```rs
#[tokio::main]
async fn main() {
    tracing_stacks::init();
    sleep.instrument(tracing::info_span!("sleep")).await;
}

async fn sleep() {
    for _ in 0..100 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
```

In the example above sleep span will be entered every 100us, then immediately exit, repeat for 100 times and then closed.
By adding [usdt probes](https://lwn.net/Articles/753601/) for each of those events it is possible to observe async runtime behaviour on demand.

Example of several debugging utilities:

```bash
sudo stacks -p usdt:./target/debug/examples/deadlock:u,switch:u deadlock
```

#### Pprof view with idle/wait time

```bash
stacksexport pprof ./stacksexport/sql/pprof/usdt_ustack_trace_wait_for_buildid.sql -b ./target/debug/examples/deadlock
```

#### Trace view with all tasks

Note that catapult repo needs to be cloned before running this command.

```bash
PATH=$PATH:~/catapult/tracing/bin stacksexport trace ./stacksexport/sql/traceview/usdt_all.sql
```

#### Trace with with slow tasks (slower than 10ms)

```bash
PATH=$PATH:~/catapult/tracing/bin stacksexport trace ./stacksexport/sql/traceview/usdt_slow_on_cpu_10ms.sql
```

#### Trace view with tasks that weren't closed

Useful for debugging stuck tasks.

```bash
PATH=$PATH:~/catapult/tracing/bin stacksexport trace ./stacksexport/sql/traceview/usdt_wait_time_not_closed.sql
```
