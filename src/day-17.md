# Day17 - BCC tcpconnect (下)

> Day 17\
> 原文：[https://ithelp.ithome.com.tw/articles/10302485](https://ithelp.ithome.com.tw/articles/10302485)\
> 發布日期：2022-10-01

我們接續昨天繼續講tcpconnect的程式碼。

後半部分的eBPG程式碼定義了`trace_connect_return`，這個函數會被attach到tcp_v4_connect和tcp_v6_connect的kretprobe上。kprobe是在函數被呼叫時被觸發，kretprobe則是在函數回傳時被觸發，因此可以取得函數的回傳值和執行結果。

``` c
int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}
```

真正的進入點分成ip v4和v6的版本來傳入ipver變數。

``` c
static int trace_connect_return(struct pt_regs *ctx, short ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }
    // pull in details
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    FILTER_PORT
    FILTER_FAMILY
    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        IPV6_CODE
    }
    currsock.delete(&tid);
    return 0;
}
```

透過`PT_REGS_RC`可以取得函數的回傳值，根據函數的定義，如果執行成功應該要回傳0所以如果`ret`不為零，表示執行錯誤，直接忽略。  
透過`currsock.lookup`我們可以取回對應tid的sock指標，然後取得dst port和src port(lport)，由於這時候tcp_connect已經執行完成，所以src port已經被kernel分配。

> 這邊可以看到eBPF程式設計上比較複雜的地方，sock結構體要在kprobe取得，但是我們又需要kretprobe後的一些資訊，因此整個架構要被拆成兩個部分，然後透過map來進行傳輸。

接著`FILTER_PORT`和`FILTER_FAMILY`一樣會被替換，然後根據dst port和family來filter。

由於tcpconnect有紀錄和統計連線次數兩種模式，因此最後一段的code一樣先被標記成`IPV4_CODE`。然後根據模式的不同來取代成不同的code。

``` python
if args.count:
    bpf_text = bpf_text.replace("IPV4_CODE", struct_init['ipv4']['count'])
    bpf_text = bpf_text.replace("IPV6_CODE", struct_init['ipv6']['count'])
else:
    bpf_text = bpf_text.replace("IPV4_CODE", struct_init['ipv4']['trace'])
    bpf_text = bpf_text.replace("IPV6_CODE", struct_init['ipv6']['trace'])
```

我們這邊就只看ipv4 trace的版本。

``` c
struct ipv4_data_t data4 = {.pid = pid, .ip = ipver};
data4.uid = bpf_get_current_uid_gid();
data4.ts_us = bpf_ktime_get_ns() / 1000;
data4.saddr = skp->__sk_common.skc_rcv_saddr;
data4.daddr = skp->__sk_common.skc_daddr;
data4.lport = lport;
data4.dport = ntohs(dport);
bpf_get_current_comm(&data4.task, sizeof(data4.task));
ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
```

這邊其實就是去填充ipv4_data_t結構、透過bpf_get_current_comm取得當前程式的名稱，最後透過前面透過BPP_PERF_OUT定義的ipv4_events，呼叫`perf_submit(ctx, &data4, sizeof(data4))`將資料送到user space。

到這邊就完成了整個的eBPF程式碼`bpf_text`的定義，後面就會先經過前面講的，將IPV4_CODE等字段，根據tcpconnect的參數進行取代。

``` python
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")
```

接著透過BCC的library完成eBPF程式碼的編譯、載入和attach。

最後是輸出的部分，前面會先輸出一些下列的欄位資訊，但是由於這不是很重要所以就省略掉。

    Tracing connect ... Hit Ctrl-C to end
    PID     COMM         IP SADDR            DADDR            DPORT 

``` python
b = BPF(text=bpf_text)
...
# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

完成載入後，我們可以拿到一個對應的BPF物件，透過b\[MAP_NAME\]，我們可以調用map對應的`open_perf_buffer`API，透過`open_perf_buffer`，我們可以定義一個callback function當有資料從kernel透過perf_submit被傳輸的時候被呼叫來處理eBPF程式送過來的資料。

最後會呼叫`b.perf_buffer_poll`來持續檢查perf map是不是有新的perf event，以及呼叫對應的callback function。

``` python
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")
    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()
    if args.lport:
        printb(b"%-7d %-12.12s %-2d %-16s %-6d %-16s %-6d %s" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(), event.lport,
            dest_ip, event.dport, print_dns(dest_ip)))
    else:
        printb(b"%-7d %-12.12s %-2d %-16s %-16s %-6d %s" % (event.pid,
            event.task, event.ip,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            dest_ip, event.dport, print_dns(dest_ip)))x
```

透過`b["ipv4_events"].event`可以直接將data數據轉換成BPF程式內定義的資料結構，方便存取。取得的資料再經過一些清洗和轉譯就能夠直接輸出了。

雖然我們跳過了count功能還有一個紀錄dst ip的DNS查詢，但到此我們大致上看完了整個tcpconnect的主要的實作內容。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
