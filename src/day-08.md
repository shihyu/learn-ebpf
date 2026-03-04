# Day8 - eBPF基本知識(5) - 生命週期

> Day 08\
> 原文：[https://ithelp.ithome.com.tw/articles/10296560](https://ithelp.ithome.com.tw/articles/10296560)\
> 發布日期：2022-09-23

在透過`bpf(BPF_PROG_LOAD, ...)` system call將eBPF程式載入內核的過程(可以參考[原始碼](https://elixir.bootlin.com/linux/v5.13/source/kernel/bpf/syscall.c#L2079))，會替該eBPF程式建立`struct bpf_prog` [結構](https://elixir.bootlin.com/linux/v5.13/source/include/linux/filter.h#L550)，其中`prog->aux->refcnt`計數器記錄了該eBPF程式的參考數量，載入的時候會透過`atomic64_set(&prog->aux->refcnt, 1);`將refcnt設置為一，並返為對應的file descriptor。

當refcnt降為0的時候，就會觸發unload，將eBPF程式資源給釋放掉。([原始碼](https://elixir.bootlin.com/linux/v5.13/source/kernel/bpf/syscall.c#L1714))  
因此如果呼叫`BPF_PROG_LOAD`的程式沒有進一步操作，並直接結束的話，當file descriptor被release，就會觸發refcnt--，而變成0並移除eBPF程式。

要增加eBPF程式refcnf大致上有幾種方式

- 透過bpf systemcall的BPF_BTF_GET_FD_BY_ID等方式取得eBPF程式對應的file descriptor
- 將eBPF程式attach到事件、Link上，使eBPF程式能真的開始工作。
  - 因此當eBPF被attach到hook points上之後，即便原始載入程式結束也不會導致eBPF程式被回收，而可以正常繼續工作。
  - Link是eBPF後來提供的新特性，因此暫時超出了本文的討論範圍
- 透過bpf systemcall的BPF_OBJ_PIN，將eBPF程式釘到BPFFS上。
  - BPFFS是BPF file system，本質上是一個虛擬的檔案系統，一樣透過bpf system call的BPF_OBJ_PIN，我們可以把eBPF程式放到`/sys/fs/bpf/`路徑下的指定位置，並透過`open`的方式直接取得file descriptor。PIN同樣會增加refcnt，因此PIN住的程式不會被回收
  - 要釋放PIN住的程式，可以使用unlink指令移除虛擬檔案，即可取消PIN。

透過以上的操作都會增加refcnt，相反的，對應的資源釋放則會減少refcnt。因此只要確保有任何一個eBPF程式的參考存在，即可保證eBPF程式一直存在kernel內。

- 參考文獻  
  <https://facebookmicrosites.github.io/bpf/blog/2018/08/31/object-lifetime.html>  
  <https://stackoverflow.com/questions/68278120/ebpf-difference-between-loading-attaching-and-linking>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
