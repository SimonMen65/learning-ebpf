#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "disk_latency.h"
#include "disk_latency.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

static int print_latency_mesg(struct disk_latency_bpf *skel){

	int pid =-1, next_pid;
	struct data_pid_t m;
	int err, fd = bpf_map__fd(skel->maps.disk_latency_map);
	while (!bpf_map__get_next_key(fd, &pid, &next_pid)){
		err = bpf_map__lookup_elem(fd, &next_pid, &m);
		if (err < 0) {
			fprintf(stderr, "failed to lookup latency: %d\n", err);
			return -1;
		}
		printf("pid: %d \t command:%s \t latency:%lld", next_pid,m.command, m.latency);
		printf("\n");
		pid = next_pid;
	}

	pid = -1;
	while (!bpf_map__get_next_key(fd, &pid, &next_pid)){
		err = bpf_map__delete_elem(fd, &next_pid);
		if (err < 0) {
			fprintf(stderr, "failed to lookup latency: %d\n", err);
			return -1;
		}
		pid = next_pid;
	}
	return 0;
}

int main()
{
    struct disk_latency_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	skel = disk_latency_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = disk_latency_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		disk_latency_bpf__destroy(skel);
        return 1;
	}

	while (1){
		sleep(0.8);
		err = print_latency_mesg(skel);
		if (err){
			break;
		}
	}

	perf_buffer__free(pb);
	disk_latency_bpf__destroy(skel);
	return -err;
}
