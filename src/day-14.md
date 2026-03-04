# Day14 - BCC 簡介

> Day 14\
> 原文：[https://ithelp.ithome.com.tw/articles/10300982](https://ithelp.ithome.com.tw/articles/10300982)\
> 發布日期：2022-09-29

前面兩周的時間我們完成了eBPF基本架構和功能的介紹，接下來一周的時間我們的主題會放在之前在在Day5的範例程式碼有出現過的BCC這個eBPF Project的介紹，並透過bcc專案的範例程式碼學習eBPF的實際的撰寫。

## BPF Compiler Collection (BCC)

BCC 是一套用於eBPF，用來有效開發 kernel 追蹤修改程式的工具集。  
BCC我覺得可以看成兩個部分:

- eBPF的python和lua的前端，透過BCC我們可以使用python和lua比較簡單的開發eBPF的應用程式，BCC將bpf system call還有eBPC程式編譯封裝成了API，並提供一系列預先定義好的巨集和語法來簡化eBPF程式。

<!-- -->

    from bcc import BPF
    b = BPF(text = """
    #include <uapi/linux/bpf.h>
    int xdp_prog1(struct xdp_md *ctx)
    {
        return XDP_DROP;
    }
    """
    fn = b.load_func("xdp_prog1", BPF.XDP)
    b.attach_xdp("eth0", fn, 0)

以上面的範例來說，透過BPF物件實立化時會完成eBPC bytecode的編譯，然後透過load_func和attach_xdp就可以很簡單的將上面的eBPF程式碼編譯載入到kernel然後attach到xdp的hook point上。

- 一系列使用自身框架開發的工具

  - BCC使用自己的API開發了一系列可以直接使用的現成bcc eBPF程式，本身就幾乎涵蓋了eBPF的所有program type，可以開箱即用，直接跳過eBPF的開發。
  - 下圖包含了BCC對linux kernel各個模組實現的工具名稱
  - ![](images/day-14-01.png)

- eBPC本身和bcc相關的開發文件以及範例程式

  - 可以看到前面很多天有參考到BCC的文件，資料非常地豐富

今天就到這邊，明天會從BCC的開發環境建置開始講。

最後附上bcc的github repo: <https://github.com/iovisor/bcc>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
