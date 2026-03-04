# Day28 - BCC sockmap (下)

> Day 28\
> 原文：[https://ithelp.ithome.com.tw/articles/10308044](https://ithelp.ithome.com.tw/articles/10308044)\
> 發布日期：2022-10-12

接續昨天介紹`BPF_PROG_TYPE_SOCK_OPS`這個處理眾多socket事件的program type之後，我們要介紹兩個program type `BPF_PROG_TYPE_SK_SKB`和`BPF_PROG_TYPE_SK_MSG`。

首先他們不attach linux本身的某個地方而是attach在一個eBPF map上，這個map必須是`BPF_MAP_TYPE_SOCKMAP`或`BPF_MAP_TYPE_SOCKHASH`。兩個map都是某個key對應到socket，可以使用sock_hash_update更新sockhash map，將昨天sock_ops的上下文bpf_sock_ops結構當作value去插入。

當sockmap裡面的socket有訊息要送出，封包要被放到socket的TXQueue時會觸發`BPF_PROG_TYPE_SK_MSG`，而當封包從外界送入被主機接收，要放到socket的RXQueue時則會觸發`BPF_PROG_TYPE_SK_SKB`。

以這次會用到的`BPF_PROG_TYPE_SK_MSG`來說，當userspace呼叫sendmsg時，就會被eBPF程式攔截。

可以透過回傳`__SK_DROP`, `__SK_PASS`, `__SK_REDIRECT`來決定是要丟棄、接收或做socket redirect。

透過socket redirect，封包會從發送端socket直接被丟到接收端socket RXQ。

> 目前redirect的功能只能用於TCP連線。

大致上的概念介紹完了就讓我們進到實際的程式碼。

首先一樣先看eBPF的程式碼。

``` c
#define MAX_SOCK_OPS_MAP_ENTRIES 65535
struct sock_key {
    u32 remote_ip4;
    u32 local_ip4;
    u32 remote_port;
    u32 local_port;
    u32 family;
};
BPF_SOCKHASH(sock_hash, struct sock_key, MAX_SOCK_OPS_MAP_ENTRIES);
```

這邊定義了一個`sock_key`，作為BPF_SOCKHASH socket map的key，透過five tuple (IP src/dst, sct/dst port及TCP/UDP)來定位一個連線。

接著我們看到第一種program type `SOCK_OPS`的入口函數。

    int bpf_sockhash(struct bpf_sock_ops *skops) {
        u32 op = skops->op;
        /* ipv4 only */
        if (skops->family != AF_INET)
        return 0;
        switch (op) {
            case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
                bpf_sock_ops_ipv4(skops);
                break;
            default:
                break;
        }
        return 0;
    }

這邊做的事情很簡單，在socket建立連線(ACTIVE_ESTABLISHED_CB)和接收連線(PASSIVE_ESTABLISHED_CB)時，呼叫bpf_sock_ops_ipv4將socket放到sock map內，讓socket被第二個program type `SK_MSG`的程式能夠在socket呼叫sendmsg等API時被攔截處理。由於socker redirect只能處裡TCP連線，所以非`AF_INET`的連線會被過濾掉。

``` c
static __always_inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops) {
    struct sock_key skk = {
        .remote_ip4 = skops->remote_ip4,
        .local_ip4  = skops->local_ip4,
        .local_port = skops->local_port,
        .remote_port  = bpf_ntohl(skops->remote_port),
        .family = skops->family,
    };
    int ret;
    bpf_trace_printk(...);
    ret = sock_hash.sock_hash_update(skops, &skk, BPF_NOEXIST);
    if (ret) {
        bpf_trace_printk("bpf_sock_hash_update() failed. %d\\n", -ret);
        return;
    }
    bpf_trace_printk(...);
}
```

這邊的bpf_sock_ops_ipv4其實也很簡單，從sock_opt裡面提取出IP地址/TCP port的資訊，填充sock_key結構，然後呼叫sock_hash_update把key-value piar塞進去sock_hash。後面的flag有`BPF_NOEXIST`, `BPF_EXIST`, `BPF_ANY`。`BPF_NOEXIST`表示只有key不在map裡面的時候可以插入。

接著是`BPF_PROG_TYPE_SK_MSG`的入口函數。

``` c
int bpf_redir(struct sk_msg_md *msg) {
    if (msg->family != AF_INET)
        return SK_PASS;
    if (msg->remote_ip4 != msg->local_ip4)
        return SK_PASS;
    struct sock_key skk = {
        .remote_ip4 = msg->local_ip4,
        .local_ip4  = msg->remote_ip4,
        .local_port = bpf_ntohl(msg->remote_port),
        .remote_port = msg->local_port,
        .family = msg->family,
    };
    int ret = 0;
    ret = sock_hash.msg_redirect_hash(msg, &skk, BPF_F_INGRESS);
    bpf_trace_printk(...);
    if (ret != SK_PASS)
        bpf_trace_printk(...);
    return ret;
}
```

首先一樣我們只能處裡TCP連線所有把非`AF_INET`的連線透過`return SK_PASS;`交回linux kernel處理。

接著由於socket redirect只在本機起作用，所以這邊簡單判斷src ip和dst ip相不相同，來判斷是否是local to local連線。

接著由於socket redirect時要從發送端的socket redirect到接收端的socket，因此我們要從socket map中找到接收端的socket，對發送端和接收端的socket來說src addres和dst address的是顛倒的，所以這邊在生sock_key時會把local和remote顛倒。

接著這邊的`msg_redirect_hash`是對`bpf_msg_redirect_hash` helper function的包裝，會嘗試從socket map找到對應的socket，然後完成redirect的設置，不過成功是回傳是SK_PASS而不是SK_REDIRECT。

到這邊就完成eBPF程式的部分了，接下來python的部分就很簡單，只是把eBPG程式掛進去。

``` python
examples = """examples:
    ./sockmap.py -c /root/cgroup # attach to /root/cgroup
"""
parser = argparse.ArgumentParser(
        description="pipe data across multiple sockets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-c", "--cgroup", required=True,
        help="Specify the cgroup address. Note. must be cgroup2")
args = parser.parse_args()
```

前面有提到SOCK_OPS要掛在一個cgroup下面，所以先吃一個cgroup路徑參數來。

``` python
bpf = BPF(text=bpf_text)
func_sock_ops = bpf.load_func("bpf_sockhash", bpf.SOCK_OPS)
func_sock_redir = bpf.load_func("bpf_redir", bpf.SK_MSG)
```

編譯eBPF程式，取得兩個入口函數

``` python
# raise if error
fd = os.open(args.cgroup, os.O_RDONLY)
map_fd = lib.bpf_table_fd(bpf.module, b"sock_hash")
bpf.attach_func(func_sock_ops, fd, BPFAttachType.CGROUP_SOCK_OPS)
bpf.attach_func(func_sock_redir, map_fd, BPFAttachType.SK_MSG_VERDICT)
```

前面提到cgroup介面是一個虛擬檔案系統，所以當然要透過open去取得對應的file descriptor。接著就是attach func_sock_ops到SOCK_OPS。  
由於func_sock_redir要attach到sock map，所以先透過bcc的API取得sock_hash map的file descripter，然後attach上去。

這樣就完成sockemap的設置，可以成功提供socket redirect的服務了!

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
