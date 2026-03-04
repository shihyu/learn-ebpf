# Day25 - eBPC tc direct

> Day 25\
> 原文：[https://ithelp.ithome.com.tw/articles/10307075](https://ithelp.ithome.com.tw/articles/10307075)\
> 發布日期：2022-10-10

接續前兩的內容，讓我們再補充聊一下`tc`

在eBPF裡面，XDP和TC兩個功能常常被拿來一起討輪，前面有提到eBPF可以做為tc actions使用來達到封包過濾之類的效果，雖然實行效果上是比不上XDP的，但是tc ingress的eBPF hook point也在kernel data path的最早期，因此也能夠提供不錯的效能，加上tc ebpf program的context是`sk_buff`，相較於`xdp_buff`，可以直接透過`__sk_buff`取得和修改更多的meta data，加上tc 在ingress和egress方向都有hook point，不像XDP只能作用在ingress方向，且tc完全不需要驅動支援即可工作，因此tc在使用彈性和靈活度上是比XDP更占優的。

> 不過tc其實也有提供offload的功能，將eBPF程式offload到網卡上面執行。

然而由於tc的hook point分成classifier和action因此無法透過單一個eBPF程式做到match-action的效果，然而大多數時候eBPF tc程式的開發並不是要利用tc系統的功能做限速等功能，而是要利用tc在kernel path極早期這點做packet mangling和filter等事項，再加上tc系統的使用學習難度相對高，因此eBPC在tc後引入了[direct-action](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=045efa82ff563cd4e656ca1c2e354fa5bf6bbda4)和[clsact](%5B%601f211a1b929c%60%5D(https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1f211a1b929c804100e138c5d3d656992cfd5622))這兩個功能。

首先介紹direct-action (da)，這個是在classifier(BPF_PROG_TYPE_SCHED_CLS)可啟用的一個選項，如果啟用da，classifier的回傳值就變成是action，和BPF_PROG_TYPE_SCHED_ACT相同，而原本的classid改成設置\_\_skb_buff-\>tc_classid來傳輸。

> 在kernel code內使用 prog-\>exts_integrated 標示是否啟用da功能

透過da可以透過單一個eBPF程式完成classifier和action的功能，降低了tc hook point對原本tc系統框架的依賴，能夠透過eBPF程式簡潔的完成功能。

在da的使用上可以參考bcc的範例 `examples/networking/tc_perf_event.py`，使用上與普通的classifer幾乎無異，只要在載入時`ipr.tc("add-filter", "bpf", me, ":1", fd=fn.fd, ... ,direct_action=True)`加上direct_action選項即可。

透過tc指令查看時也可以看到`direct-action`字樣。

``` shell
tc filter show dev t1a
filter parent 1: protocol all pref 49152 bpf chain 0 
filter parent 1: protocol all pref 49152 bpf chain 0 handle 0x1 flowid :1 hello direct-action not_in_hw id 308 tag 57cd311f2e27366b jited 
    action order 1: gact action pass
     random type none pass val 0
     index 2 ref 1 bind 1
```

後來tc加入了clsact，clsact是一個專為eBPF設計的偽qdisc。首先clsact同時作用在ingress和egress方向，也進一步簡化了ebpf程式的掛載。

    tc qdisc add dev em1 clsact
    tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
    tc filter add dev em1 egress bpf da obj tc-example.o sec egress

同時clsact工作在真的qdisc本身的lock之前，因此可以避免lock的開銷，預先完成比較複雜繁重的封包分類，在進入到真的queue filter時只根據更簡單的欄位(如tc_index)做分類。另外da本來只能使用在ingress方向，透過clsact，da可以工作在egress方向。

關於eBPF tc的部分就大致上介紹到這裡，對於tc這個子系統相對來說是真的蠻陌生的，因此介紹這個部分的確是有比較大的難度和說不清楚的地方。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
