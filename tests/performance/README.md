# ndpiReader flow-table benchmark

Build and run the table benchmark with:

```sh
make -C tests/performance flow_table_bench
tests/performance/flow_table_bench 50000 400000 512
```

The output compares the old 512-way segmented binary tree with the new
segmented open-addressing table using the same generated flows and lookup
sequence:

```text
backend,flows,lookups,insert_cpu_sec,lookup_cpu_sec,pps,ns_per_lookup,memory_bytes,avg_probes
segmented_tree,...,n/a
open_addressing,...,<probe count>
```

`pps` is derived from lookup CPU time (`lookups / CPU seconds`) and
`memory_bytes` includes both the flow records and the table index.  The tree
row depends on the implementation-specific `tsearch` node overhead; its
estimate uses three pointers per flow, matching nDPI's tree node.

Run the semantic regression check with:

```sh
make -C tests/performance flow_table_test
```

It inserts the same flows into both implementations, performs random
forward/reverse lookups, removes a subset (creating tombstones), and verifies
that both tables agree on every lookup.

For end-to-end throughput, run ndpiReader on a representative capture and
compare its `nDPI throughput: ... pps` line before and after the change:

```sh
./example/ndpiReader -i capture.pcap
```
