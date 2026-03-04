# Day24 - BCC neighbor_sharing

> Day 24\
> 原文：[https://ithelp.ithome.com.tw/articles/10306634](https://ithelp.ithome.com.tw/articles/10306634)\
> 發布日期：2022-10-09

接續昨天tc的話題，今天讓我們再回到trace BCC的程式碼，這次要看的是`examples/networking/neighbor_sharing`。([原始碼](https://github.com/iovisor/bcc/blob/master/examples/networking/neighbor_sharing/))

這次的eBPF程式會提供QoS的服務，對經過某張網卡的針對往特定的IP提供不同的限速群組。

                             /------------\                        |
    neigh1 --|->->->->->->->-|            |                        |
    neigh2 --|->->->->->->->-|    <-128kb-|        /------\        |
    neigh3 --|->->->->->->->-|            |  wan0  | wan  |        |
             | ^             |   br100    |-<-<-<--| sim  |        |
             | clsfy_neigh() |            |   ^    \------/        |
    lan1 ----|->->->->->->->-|    <--1Mb--|   |                    |
    lan2 ----|->->->->->->->-|            |   classify_wan()       |
               ^             \------------/                        |
               pass()                                              |

上圖是neighbor_sharing自帶的網路拓譜圖，neight1-3, lan1-2, wan0是獨立的network namespace擁有獨立的IP，neighbor_sharing會在wansim到br100的介面上建立`ingress tc`，針對neigh1-3的IP提供總共128kb/s的網路速度，對其他IP提供總共1024kb/s的網路速度。

首先在測試之前要先安裝pyroute2和netperf，前者是python接接tc指令的library，後者是用來測試網速的工具。另外要記得設置防火牆規則不然br100不會轉發封包

``` shell
pip3 install pyroute2
apt install netperf
iptables -P FORWARD ACCEPT
sysctl -w net.ipv4.ip_forward=1
```

neight1-3會被分配172.16.1.100-102的IP, lan則是172.16.1.150-151。

``` shell
sudo ip netns exec wan0 netperf -H 172.16.1.100 -l 2 -k
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 172.16.1.100 () port 0 AF_INET : demo
Recv   Send    Send
Socket Socket  Message  Elapsed
Size   Size    Size     Time     Throughput
bytes  bytes   bytes    secs.    10^6bits/sec

 131072  16384  16384    6.00      161.45
```

透過netperf可以測出來到neight1的封包流量被限制在約161.45 kbits/sec。

``` shell
ip netns exec wan0 netperf -H 172.16.1.150 -l 2 -f k
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 172.16.1.150 () port 0 AF_INET : demo
Recv   Send    Send                          
Socket Socket  Message  Elapsed              
Size   Size    Size     Time     Throughput  
bytes  bytes   bytes    secs.    10^3bits/sec  

131072  16384  16384    2.67     1065.83 
```

而到lan1大約是1065.83kbits/sec，接近預先設置的規則。

首先，eBPF在tc系統裡面是在`filter`的部分作用，並可分成兩種模式classifier(BPF_PROG_TYPE_SCHED_CLS)和action(BPF_PROG_TYPE_SCHED_ACT)。

- classifier: 前者分析封包後，決定是否match，並可以將封包分類給透過tc指令預設的classid或著重新指定classid。

  - 0: mismatch
  - -1: match, 使用filter預設的classid
  - 直接回傳一個classid

- action: 作為該`filter`的action，當tc設置的filter規則match後，呼叫eBPF程式決定action是drop(2), 執行預設action(-1)等。  
  下列是action的完整定義

``` c
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK       0
#define TC_ACT_RECLASSIFY   1
#define TC_ACT_SHOT     2
#define TC_ACT_PIPE     3
#define TC_ACT_STOLEN       4
#define TC_ACT_QUEUED       5
#define TC_ACT_REPEAT       6
#define TC_ACT_REDIRECT     7
#define TC_ACT_JUMP     0x10000000  
```

這次會先看python的程式碼，由於這次的程式碼包含大量用來建立測試環境的部分，所以會跳過只看相關的內容。

``` c
b = BPF(src_file="tc_neighbor_sharing.c", debug=0)

wan_fn = b.load_func("classify_wan", BPF.SCHED_CLS)
pass_fn = b.load_func("pass", BPF.SCHED_CLS)
neighbor_fn = b.load_func("classify_neighbor", BPF.SCHED_CLS)
```

首先這次的eBPF程式包含三個部分，因此會分別載入，並且全部都是classifier(BPF_PROG_TYPE_SCHED_CLS)

``` python
ipr.tc("add", "ingress", wan_if["index"], "ffff:")
ipr.tc("add-filter", "bpf", wan_if["index"], ":1", fd=wan_fn.fd,
       prio=1, name=wan_fn.name, parent="ffff:", action="drop",
       classid=1, rate="128kbit", burst=1024 * 32, mtu=16 * 1024)
ipr.tc("add-filter", "bpf", wan_if["index"], ":2", fd=pass_fn.fd,
       prio=2, name=pass_fn.name, parent="ffff:", action="drop",
       classid=2, rate="1024kbit", burst=1024 * 32, mtu=16 * 1024)
```

接著會建立wan_if的ingress qdisc (wan_if是wan0接到br100的介面)，並且會ingress qdisc下建立兩條filter，首先它的type 指定為bpf並透過`fd=wan_fn.fd`選定eBPF program，所以會交由eBPF classifier來決定是不是要match。

> classifier match後就會執行下屬的policing action，跟classid無關，且在這次的範例中並不存在class，所以classid其實是無意義的，不一定要設置。

後半段`action="drop", rate="128kbit", burst=1024 * 32, mtu=16 * 1024`定義了一條policing action，只有當封包滿足policy條件時才會觸發具體的action，這邊指定是流量超出128kbit時執行drop，也就達到了限制neigh流量的效果。

第二條同理，match pass_fn並且流量到達1024kbit時執行drop，由於pass_fn顧名思義是無條件match的意思，所以等價於所有非neigh的流量共用這一條的1024kbit流量限制。

因此總結來說，eBPF程式wan_fn透過某種方式判斷封包是否是往neigh的ip，是的話就match 第一條filter執行policing action來限流，不然就match 第二條filter來做限流。

``` python
ret = self._create_ns("neighbor%d" % i, ipaddr=ipaddr,
                                  fn=neighbor_fn, cmd=cmd)
```

接著就會看到，在建立neigh1-3的namespace時，attach了neighbor_fn到網卡上，因此就很好理解了neighbor_fn監聽了從neigh發出的封包，解析拿到neigh的IP後，透過map share給wan_fn，讓wan_fn可以根據ip決定要不要match第一條policing action。

到這裡其實就分析出整個程式的執行邏輯了，我們接續來看看neighbor_sharing的eBPF程式，這次的eBPF程式分成三個部分，首先是接在每個neigh ingress方向的classify_neighbor，接著是接在wan0 ingress方向的classify_wan和pass。

前面說到出來`classify_neighbor`要做的事情就是紀錄neigh1-3的IP，提供給`classify_wan`判斷是否要match封包，執行128kbits的流量限制。

``` c
struct ipkey {
  u32 client_ip;
};

BPF_HASH(learned_ips, struct ipkey, int, 1024);
```

首先定義了一個hash map用key來儲存所有neigh的IP

``` c
int classify_neighbor(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
      case ETH_P_IP: goto ip;
      default: goto EOP;
    }
  }
  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 sip = ip->src;
    struct ipkey key = {.client_ip=sip};
    int val = 1;
    learned_ips.insert(&key, &val);
    goto EOP;
  }
EOP:
  return 1;
}
```

接著`classify_neighbor`就會用cursor解析出source ip，將其作為hash map的key放到learned_ips裡面，value則都設為1。不論如何都會return 1放行封包。雖然其實這是neighbor ingress方向上唯一的一條filter，所以不論回傳值為多少其實都可以，不影響執行結果。

> 這邊就要提到第一次學習tc還有classifier時會感到很困惑的地方了，首先classifier的回傳值0表示mismatch, 1表示match並轉移到預設的class，其餘回傳值表示直接指定classid為回傳的數值。接著不論classid是多少，都會執行filter上面綁定的action。在這次的範例中，所有的filter其實都不存在任何的class，因此return值唯一的意義是控制是否要執行action。這邊classify_neighbor綁定的action是ok，表示放行封包的意思

``` c
int classify_wan(struct __sk_buff *skb) {
  u8 *cursor = 0;
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    switch (ethernet->type) {
      case ETH_P_IP: goto ip;
      default: goto EOP;
    }
  }
  ip: {
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 dip = ip->dst;
    struct ipkey key = {.client_ip=dip};
    int *val = learned_ips.lookup(&key);
    if (val)
      return *val;
    goto EOP;
  }
EOP:
  return 0;
}
```

接著看到`classify_wan`，他會提取封包的dst ip address，並嘗試搜尋learned_ips，如果找的到就表示這個是neighbor的ip，回傳map對應的value，前面提到所有的value都會設置為1，因此表示match的意思，不然就跳轉到EOP回傳0，表示mismatch。同樣由於這邊不存在class，因此value只要是非0即可，只是用來match執行policing action。

``` c
int pass(struct __sk_buff *skb) {
  return 1;
}
```

最後的`pass`其實就是一條無條件回傳1表示match，來執行wan0方向第二條1024kbits/sec的限流政策用的。

到這邊我們就把`neighbor_sharing`講完了，不過其實tc還有許多可以探討的議題，就讓我們留到明天再來講。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
