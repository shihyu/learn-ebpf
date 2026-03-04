# Day13 - eBPF基本知識(10) - Tail call

> Day 13\
> 原文：[https://ithelp.ithome.com.tw/articles/10300161](https://ithelp.ithome.com.tw/articles/10300161)\
> 發布日期：2022-09-28

eBPF的基本知識部分來到了第10章，剛好也就是這個部分的最後一章，今天我們要來聊的是tail call的功能。

tail call簡單來說就是在eBPF程式內執行另外一個eBPF程式，不過和一般的函數呼叫不一樣，eBPF虛擬機在跳轉到另外一個eBPF程式後就不會再回到前一個程式了，所以他是一個單向的呼叫。

另外雖然他會直接複用前一個eBPF程式的stack frame，但是被呼叫的eBPF程式不能夠存取前呼叫者的暫存器和stack，只能透取得在呼叫tail call時，透過參數傳遞的`ctx`。

使用tail call可以透過拆解簡化一個eBPF程式，打破單個eBPF程式只能有512bytes的stack、1 million個指令的限制。

一個使用範例是先使用一個eBPF程式作為packet dispatcher，然後根據不同的packet ether type之類的欄位，將packet轉發給對應處理的eBPF程式。

另外一個就是將eBPF程式視為多個模組，透過map和tail call去動態的任意重整排序執行結構。

為了避免eBPF程式交替呼叫彼此導致卡死的狀況，kernel定義了`MAX_TAIL_CALL_CNT`表示在單個context下最多可呼叫的tail call次數，目前是32。如果tail call因為任何原因而執行失敗，則會繼續執行原本的eBPF程式。

### 如何使用

tail call的helper function定義如下`long bpf_tail_call(void *ctx, struct bpf_map *prog_array_map, u32 index)`。在使用的時候我們要一個`BPF_MAP_TYPE_PROG_ARRAY` type的map，用來保存一個eBPF program file descriptor的陣列。在呼叫tail call的時候傳遞進去執行。

eBPF的基本知識部分到這邊就結束拉，明天開始會是新的篇章。

- 參考文件  
  <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>  
  <https://lwn.net/Articles/645169/>  
  <https://www.readfog.com/a/1663618518017478656>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
