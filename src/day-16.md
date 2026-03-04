# Day16 - BCC tcpconnect (上)

> Day 16\
> 原文：[https://ithelp.ithome.com.tw/articles/10302466](https://ithelp.ithome.com.tw/articles/10302466)\
> 發布日期：2022-10-01

我們今天要來看的是`tools/tcpconnect.py`這支程式。原始碼在[這邊](https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py)。

這隻程式會追蹤紀錄kernel發起的TCP連線

    python3 tools/tcpconnect 
    Tracing connect ... Hit Ctrl-C to end
    PID     COMM         IP SADDR            DADDR            DPORT 
    2553    ssh          4  10.0.2.15        10.0.2.1         22     
    2555    wget         4  10.0.2.15        172.217.160.100  80 

執行結果大概長這樣，可以看到發起連線的pid, 指令名稱，ip version, IP地址和目標port等資訊。

首先透過`argparse`定義了指令的參數輸入，主要是提供filter的選項，讓使用者可以透過pid, uid, namespace等參數去filter連線紀錄。

``` python
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
...
args = parser.parse_args()
```

接著就來到主要的eBPF程式碼的定義

``` python
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);
...
```

首先可以看到`BPF_HASH`，這是BCC提供的一個巨集，用來定一個hash type的map，對於不同map type BCC都定義了對應的巨集來建立map。具體列表可以參考[這邊](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps)。  
第一個參數是map的名稱，這邊叫做currsock，同時這個變數也用於後續程式碼中對map的參考和API呼叫，例如`currsock.lookup(&tid);`就是對currsock這個map進行lookup操作。  
接著兩個欄位分別對應key和value的type，key是一個32位元整數，value則對應到sock struct指標。sock結構在[net/sock.h](https://elixir.bootlin.com/linux/latest/source/include/net/sock.h#L352)內定義，是linux kernel用來維護socket的資料結構。

``` c
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
...
```

接著分別針對ipv4和ipv6定義了一個data_t的資料結構，用於bpf和userspace client之間傳輸tcp connect的資訊用。

這邊可以看到另外一個特別的巨集`BPF_PERF_OUTPUT`。這邊用到了eBPF提供的perf event機制，定義了一個per-CPU的event ring buffer，並提供了對應的bpf_perf_event_output helper function來把資料推進ring buffer給userspace存取。  
在bcc這邊則使用`ipv4_events.perf_submit(ctx, &data, sizeof(data));`的API來傳輸資料。

``` c
// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);
```

接著又是一個HASH map，tcpdconnect提供一個功能選項是統計各種connection的次數，所以這邊定義了一個ipv4_flow_key_t當作key來作為統計依據，`BPF_HASH`在預設情況下value的type是`u64`，一個64位元無號整數，因此可以直接拿來統計。

接著就來到了bpf函數主體，這個函數會被attach到tcp_v4_connect和tcp_v6_connect的kprobe上，當呼叫tcp_v4_connect和tcp_v6_connect時被觸發。

``` c
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);
    return 0;
};
```

首先它接收的參數是pt_regs結構和tcp_v4_connect的參數，pt_regs包含了CPU佔存器的數值資訊，作為eBPF的上下文。後面tcp_v4_connect的第一個參數sock結構對應到當次連線的socket資訊，由於後面幾個參數不會使用到所以可以省略掉。

    ./tcpconnect --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcpconnect --mntnsmap mappath   # only trace mount namespaces in the map

首先呼叫的是`container_should_be_filtered`。在argparser中定義了兩個參數cgroupmap和mntnsmap用來針對特定的cgroups或mount namespace。`container_should_be_filtered`則會負責這兩項的檢查。

一開始看可能會發現在eBPF程式裡面找不到這個函數定的定義，由於這兩個filter非常常用因此bcc定義了`bcc.containers.filter_by_containers`[函數](https://github.com/iovisor/bcc/blob/master/src/python/bcc/containers.py)，在python程式碼裡面會看到，`bpf_text = filter_by_containers(args) + bpf_text`。  
以cgroup來說，如果使用者有提供`cgroupmap`這個參數，`filter_by_containers`會在mappath透過`BPF_TABLE_PINNED`在BPFFS建立一個hash type的map，根據這個map的key來filter cgroup id，透過`bpf_get_current_cgroup_id()`取得當前上下文的cgroup_id並只保留有在map內的上下文。

接著`FILTER_PID`和`FILTER_UID`分別是針對pid和uid去filter，在後面的python程式碼中會根據是否有啟用這個選項來把字串替代成對應的程式碼或空字串

    if args.pid:
        bpf_text = bpf_text.replace('FILTER_PID',
            'if (pid != %s) { return 0; }' % args.pid)
    bpf_text = bpf_text.replace('FILTER_PID', '')

如果一切都滿足，就會使用tid當key，將sock結構更新到`currsock` map當中。

到此我們只處存了tid和最新的sock的資料，`currsock`不用於把資料發送到userspace client。而是要等到後半部的程式碼處理。明天我們接續講解後半部分的程式碼。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
