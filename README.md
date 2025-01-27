# ebpf-prog-metrics

eBPF Program Metrics Exporter

**NOTE**: Until ebpf-go supports `*btf.Var` in the `.ksyms` data section, this is kinda not possible in Go.

Ref: https://github.com/Netflix/bpftop/blob/main/src/bpf/pid_iter.bpf.c

## Compile and run using libbpf
```
clang -g -O2 -target bpf -c metrics.bpf.c -o metrics.bpf.o
bpftool gen skeleton metrics.bpf.o > metrics.skel.h
clang -g -O2 -Wall metrics.c libbpf/build/libbpf.a -lelf -lz -o exporter
```
