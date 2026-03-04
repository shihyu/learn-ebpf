# Day4 - eBPF基本知識(1) - Program type

> Day 04\
> 原文：[https://ithelp.ithome.com.tw/articles/10294364](https://ithelp.ithome.com.tw/articles/10294364)\
> 發布日期：2022-09-19

接下來幾天會介紹一些eBPF裡面的重要概念還有eBPF的載入流程

首先要介紹的是Program type。  
我們可以把eBPF程式區分成不同的BPF program type，不同的program type代表實現不同功能的eBPF程式。根據program type的不同，eBPF程式的輸入和輸出格式就不同，也影響到不同的kernal組件。

到目前Linux kernal 5.19版，linux總共定義了32種的program type。在linux kernal source code的 [include/uapi/linux/bpf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) 中定義了`bpf_prog_type`列舉，列舉了所有的program type。

    enum bpf_prog_type {
        BPF_PROG_TYPE_UNSPEC,
        BPF_PROG_TYPE_SOCKET_FILTER,
        BPF_PROG_TYPE_KPROBE,
        BPF_PROG_TYPE_SCHED_CLS,
        BPF_PROG_TYPE_SCHED_ACT,
        BPF_PROG_TYPE_TRACEPOINT,
        BPF_PROG_TYPE_XDP,
        BPF_PROG_TYPE_PERF_EVENT,
        BPF_PROG_TYPE_CGROUP_SKB,
        BPF_PROG_TYPE_CGROUP_SOCK,
        ...
    };

以`BPF_PROG_TYPE_XDP`為例，XDP是`Express Data Path`的縮寫，XDP程式會在封包從網路卡進入到kernal的最早期被觸發。  
kernal會帶入xdp_md資料結構作為eBPF程式的輸入，包含了封包的內容、封包的來源介面等資訊。

    // include/uapi/linux/bpf.h

    /* user accessible metadata for XDP packet hook */
    struct xdp_md {
        __u32 data;
        __u32 data_end;
        __u32 data_meta;

        /* Below access go through struct xdp_rxq_info */
        __u32 ingress_ifindex; /* rxq->dev->ifindex */
        __u32 rx_queue_index;  /* rxq->queue_index  */
        __u32 egress_ifindex;  /* txq->dev->ifindex */
    };

eBPF程式必須回傳一個`xdp_action`，包含`XDP_PASS`表示封包可以繼續通過到kernal network stack，`XDP_DROP`表示直接丟棄該封包。

``` c
// include/uapi/linux/bpf.h

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};
```

透過這樣的eBPF程式，我們就可以在封包剛進入kernal的時候直接丟棄非法封包，能夠有效的處理DDos攻擊等問題。  
以此可以寫出一個極簡單的eBPF程式範例 (只包含最主要的部份，完整的程式寫法會在後面提到)

    int xdp_prog_simple(struct xdp_md *ctx)
    {
        return XDP_DROP;
    }

這個eBPF程式可以被attach到某一個interface上，當封包進來時會被呼叫。由於無條件回傳XDP_DROP，因此會丟棄所有的封包。

參考文獻

- <https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types>
- <https://arthurchiao.art/blog/bpf-advanced-notes-1-zh/>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
