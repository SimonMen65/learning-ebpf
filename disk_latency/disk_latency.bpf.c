#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "disk_latency.h"

char message[12] = "Hello World";
char messageD[20] = "Disk Read Not Found";
char messageFD[16] = "Disk Read Found";

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
    __type(value, struct data_pid_t);
} disk_latency_map SEC(".maps");

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
   data.latency = (u64)(ts - *start_time);

   bpf_map_update_elem(&disk_latency_map, &pid, &data, BPF_ANY);
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
