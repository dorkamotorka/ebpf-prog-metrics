# ebpf-prog-metrics

eBPF Program Metrics Exporter

**NOTE**: Until ebpf-go supports `*btf.Var` in the `.ksyms` data section, this is kinda not possible in Go.

**NOTE**: Also `libbpfgo` currently does not support attaching eBPF iterators.

eBPF Kernel program inspired from: https://github.com/Netflix/bpftop/blob/main/src/bpf/pid_iter.bpf.c
