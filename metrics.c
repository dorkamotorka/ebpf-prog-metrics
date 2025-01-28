//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

static const char *get_name(struct btf *btf, long btf_id, const char *fallback)
{
	struct btf_type **types, *t;
	unsigned int name_off;
	const char *str;

	if (!btf) {
		return fallback;
	}

	str = btf->strings;
	types = btf->types;
	bpf_probe_read_kernel(&t, sizeof(t), types + btf_id);
	name_off = BPF_CORE_READ(t, name_off);

	if (name_off >= btf->hdr.str_len) {
		return fallback;
	}

	return str + name_off;
}

SEC("iter/bpf_prog")
int dump_bpf_prog(struct bpf_iter__bpf_prog *ctx) {
	struct seq_file *seq = ctx->meta->seq;
	__u64 seq_num = ctx->meta->seq_num;
	struct bpf_prog *prog = ctx->prog;
	struct bpf_prog_aux *aux;

	if (!prog) {
		return 0;
	}

	aux = prog->aux;
	if (seq_num == 0) {
		BPF_SEQ_PRINTF(seq, "  id name             attached\n");
	}

	BPF_SEQ_PRINTF(seq, "%4u %-16s %s %s\n", aux->id,
		       get_name(aux->btf, aux->func_info[0].type_id, aux->name),
		       aux->attach_func_name, aux->dst_prog->aux->name);
	return 0;
}
