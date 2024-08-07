#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello-buffer-config.h"

char message[12] = "Hello World";
char messageD[20] = "Disk Read Not Found";
char messageFD[16] = "Disk Read Found";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct user_msg_t {
   char message[12];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} pid_start_time_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} disk_latency_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output_disk SEC(".maps");

// SEC("ksyscall/execve")
// int BPF_KPROBE_SYSCALL(hello, const char *pathname)
// {
//    struct data_t data = {}; 
//    struct user_msg_t *p;

//    data.pid = bpf_get_current_pid_tgid() >> 32;
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

//    bpf_get_current_comm(&data.command, sizeof(data.command));
//    bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

//    p = bpf_map_lookup_elem(&my_config, &data.uid);
//    if (p != 0) {
//       bpf_probe_read_kernel_str(&data.message, sizeof(data.message), p->message);
//    } else {
//       bpf_probe_read_kernel_str(&data.message, sizeof(data.message), message); 
//    }

//    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
//    return 0;
// }

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read)
{
   u32 pid = bpf_get_current_pid_tgid() >> 32;
   u64 ts = bpf_ktime_get_ns();
   bpf_map_update_elem(&pid_start_time_map, &pid, &ts, BPF_ANY);
   return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(kretprobe_vfs_read){
   struct data_pid_t data = {}; 
   u64* start_time;
   u32 pid = bpf_get_current_pid_tgid() >> 32;

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   u64 ts = bpf_ktime_get_ns();

   start_time = bpf_map_lookup_elem(&pid_start_time_map, &pid);
   if (!start_time){
      return 0;
   }
   u64 delta = (u64)(ts - *start_time);

   if (start_time != 0) {
      bpf_probe_read_kernel_str(&data.message, sizeof(data.message), messageFD);
      bpf_map_delete_elem(&pid_start_time_map, &pid);
      data.latency = ts;
   } else {
      bpf_probe_read_kernel_str(&data.message, sizeof(data.message), messageD); 
      data.latency = ts;
   }


   bpf_map_update_elem(&disk_latency_map, &pid, &delta, BPF_ANY);

   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
