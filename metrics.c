#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "metrics.skel.h"

struct pid_iter_entry {
	__u32 id;
	int pid;
	char comm[16];
};

int main(void)
{
    struct metrics_bpf *obj;
    struct pid_iter_entry buf;
    int iter_fd;
    ssize_t ret;
    int err;

    struct rlimit rlim = {
        .rlim_cur = 512UL << 20,
        .rlim_max = 512UL << 20,
    };

    err = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (err) {
        fprintf(stderr, "failed to change rlimit\n");
        return 1;
    }

    obj = metrics_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        return 1;
    }

    err = metrics_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }
    
    iter_fd = bpf_iter_create(bpf_link__fd(obj->links.bpftop_iter));
    if (iter_fd < 0) {
	err = -1;
	fprintf(stderr, "Failed to create iter\n");
	goto cleanup;
    }

    fprintf(stdout, "eBPF program running\n");

    // Infinite loop to keep the program running
    while (true) {
	    ret = read(iter_fd, &buf, sizeof(struct pid_iter_entry));
	    if (ret < 0) {
		    if (errno == EAGAIN) {
			continue;
		    }
		    	
		    err = -errno;
		    break;
	    }

	    if (ret == 0) {
		    break;
	    }
		
	    printf("ID: %d. Pid: %d. Process Name: %s.\n", buf.id, buf.pid, buf.comm);
    }

cleanup:
    close(iter_fd);
    metrics_bpf__destroy(obj);
    return err != 0;
}
