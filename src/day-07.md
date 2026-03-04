# Day7 - eBPF基本知識(4) - JIT

> Day 07\
> 原文：[https://ithelp.ithome.com.tw/articles/10296128](https://ithelp.ithome.com.tw/articles/10296128)\
> 發布日期：2022-09-22

接續昨天的內容，當eBPF程式通過verifier的驗證之後會進行JIT(Just In Time)的二次編譯。之前一直提到eBPF是一個執行在kernel內的虛擬機，因此編譯出來的bytecode需要再執行的過程中在轉換成machine code，才能夠真正在CPU上面執行，然而這樣的虛擬化和轉換過程，會造成eBPF程式的執行效率，比直接執行machine code要低上很多。

因此eBPF加入了JIT的功能，簡單來說就是把eBPF的bytecode預先在載入的時候，直接編譯成CPU可執行的machine code，在執行eBPF程式的時候就可以直接執行，而不用再經過eBPF虛擬機的轉換，使eBPF可以達到原生程式的執行效率。

由於JIT需要編譯出machine code，因此針對不同的CPU平台他的支援是分開的，不過當然到了現在，基本上大部分主流的CPU架構(x86, ARM, RISC, MIPS...)都已經支援了，具體的支援情況可以參考這張表。https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#jit-compiling

同樣JIT是eBPF的一個可開關的獨立功能，透過設置bpf_jit_enable來啟用JIT的功能

    systcl -w net.core.bpf_jit_enable=1

(設置為2的話，可以在kernel log看到相關日誌)

到此eBPF程式就就完成載入了，雖然在eBPF程式的載入過程中還會完成一些資料結構的建立和維護，但是這個部分就不再本文的範圍內了。

當然到此eBPF程式只是載入到了內核之中，並未連接到任何的hook point，因此到此為eBPF程式還未能真正被執行，不過這就是後面的故事了。

- 備註: 從kernel source code來看，在eBPF程式載入的過程中會呼叫[bpf_prog_select_runtime](https://elixir.bootlin.com/linux/v5.13/source/kernel/bpf/core.c#L1840)來判斷是否要呼叫JIT compiler去編譯，有興趣可以去trace這部分的code。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
