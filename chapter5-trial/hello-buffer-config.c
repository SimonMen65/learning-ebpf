#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_pid_t *m = data;

	printf("%-6d %-6d %-16s %-16s %-6lld\n", m->pid, m->uid, m->command, m->message, m->latency);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

static int print_latency_mesg(struct hello_buffer_config_bpf *skel){

	int pid =-1, next_pid;
	__u64 latency;
	int err, fd = bpf_map__fd(skel->maps.disk_latency_map);
	while (!bpf_map_get_next_key(fd, &pid, &next_pid)){
		err = bpf_map_lookup_elem(fd, &next_pid, &latency);
		if (err < 0) {
			fprintf(stderr, "failed to lookup latency: %d\n", err);
			return -1;
		}
		printf("pid: %d \t latency:%lld", next_pid,latency);
		printf("\n");
		pid = next_pid;
	}
	pid = -1;
	while (!bpf_map_get_next_key(fd, &pid, &next_pid)){
		err = bpf_map_delete_elem(fd, &next_pid, &latency);
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
    struct hello_buffer_config_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	skel = hello_buffer_config_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = hello_buffer_config_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_buffer_config_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_buffer_config_bpf__destroy(skel);
        return 1;
	}

	// while (true) {
	// 	err = perf_buffer__poll(pb, 100 /* timeout, ms */);
	// 	// Ctrl-C gives -EINTR
	// 	if (err == -EINTR) {
	// 		err = 0;
	// 		break;
	// 	}
	// 	if (err < 0) {
	// 		printf("Error polling perf buffer: %d\n", err);
	// 		break;
	// 	}
	// }

	while (1){
		sleep(2);
		err = print_latency_mesg(skel);
		if (err){
			break;
		}
	}

	perf_buffer__free(pb);
	hello_buffer_config_bpf__destroy(skel);
	return -err;
}
