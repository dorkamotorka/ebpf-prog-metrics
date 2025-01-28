#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

extern const void bpf_prog_fops __ksym;

struct pid_iter_entry {
	__u32 id;
	int pid;
	char comm[16];
};

SEC("iter/task_file")
int bpftop_iter(struct bpf_iter__task_file *ctx)
{
	struct file *file = ctx->file;
	struct task_struct *task = ctx->task;
	struct pid_iter_entry e;

	if (!file || !task) {
		return 0;
	}

	__u64 sum_exec_runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
	bpf_printk("sum_exec_runtime: %d", sum_exec_runtime);

	if (file->f_op != &bpf_prog_fops) {
		return 0;
	}

	__builtin_memset(&e, 0, sizeof(e));

	e.pid = BPF_CORE_READ(task, tgid);
	e.id = BPF_CORE_READ((struct bpf_prog *)file->private_data, aux, id);

	bpf_probe_read_kernel_str(&e.comm, sizeof(e.comm), task->group_leader->comm);

	bpf_printk("bpf_seq_write executed...");
	bpf_seq_write(ctx->meta->seq, &e, sizeof(e));

	return 0;
}
