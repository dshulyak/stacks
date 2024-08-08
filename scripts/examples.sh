#!/bin/bash

./target/debug/examples/pingpong_sync -i 10000
./target/debug/examples/pingpong_async -i 10000
./target/debug/examples/lock
./target/debug/examples/sleep
./target/debug/examples/rss
./target/debug/examples/writer /tmp/test.dat