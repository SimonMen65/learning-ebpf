struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
};

struct data_pid_t {
    int pid;
    int uid;
    char command[20];
    char message[20];
    __u64 latency;
};

