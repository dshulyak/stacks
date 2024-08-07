| TYPE       | NAME            | RUNTIME NS  | RUNTIME CNT | AVG NS | CNT PER SECOND |
|------------|-----------------|-------------|-------------|--------|----------------|
| tracepoint | switch_noidle   | 22857313743 | 14084081    | 1622   | 6866.93        |
| perf_event | perf_clock_noid | 3169215503  | 4795388     | 660    | 2338.07        |
| tracepoint | irq_handler_ent | 811890819   | 782352      | 1037   | 381.45         |
| tracepoint | irq_handler_exi | 1351087783  | 782352      | 1726   | 381.45         |
| tracepoint | softirq_entry   | 1902112406  | 3487960     | 545    | 1700.61        |
| tracepoint | softirq_exit    | 3850937954  | 3487960     | 1104   | 1700.61        |



## Dependendencies for vendored build

```sh
sudo apt install -y build-essential autoconf clang-14 flex bison pkg-config
sudo ln -s /usr/include/asm-generic /usr/include/asm
sudo rm -f /bin/clang && sudo ln -s /usr/bin/clang-14 /bin/clang

sudo snap install rustup --classic
rustup default stable
```