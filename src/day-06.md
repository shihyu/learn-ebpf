# Day6 - eBPF基本知識(3) - 使用條件與載入流程

> Day 06\
> 原文：[https://ithelp.ithome.com.tw/articles/10295858](https://ithelp.ithome.com.tw/articles/10295858)\
> 發布日期：2022-09-21

## 使用條件

在開始玩eBPF之前，我們要先確定一下我們的環境能夠使用eBPF。最早在kernal 3.15版加入了eBPF功能。後續在3.15到現在的5.19版間，eBPF陸陸續續加入了許多新的功能，因此開發的時候，如果不是使用最新版的作業系統，就可能會需要確認一下版本是否支援，各個功能支援的版本可以在[這邊](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)參考

另外就是eBPF的功能需要在編譯kernel的時候啟用，大部分的發行版應該都直接啟用了，不過如果使用時出現問題可能還是到`/proc/config.gz`或`/boot/config-<kernel-version>`檢查內核編譯的設定，是否有開啟`CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`還有其他BPF相關Kernal選項。  
設定可以參考bcc的[安裝需求](https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration)

## 載入流程

[圖片原址：https://ebpf.io/static/loader-dff8db7daed55496f43076808c62be8f.png](https://ebpf.io/static/loader-dff8db7daed55496f43076808c62be8f.png)

  
當eBPF程式編譯完成後，就需要透過`bpf` system call ([原始碼](https://elixir.bootlin.com/linux/v5.13/source/kernel/bpf/syscall.c#L4369))，將編譯後的bytecode載入kernel內執行。

為了安全性考量，要掛載eBPF程式需要root權限或`CAP_BPF` capability，不過目前也有在設計讓非root權限帳號能載入eBPF程式，因此將`kernel.unprivileged_bpf_disabled` sysctl設置為false的情況下，非root帳號是有能力能夠使用`BPF_PROG_TYPE_SOCKET_FILTER`的eBPF程式。

eBPF程式需要嵌入到kernel執行，因此eBPF程式的安全性是極為重要的，也要避免eBPF程式的錯誤有可能會導致kernel崩潰或卡死，因此每個載入kernel的eBPF程式都要先經過接著verifier檢查。

首先eBPF程式必須要在有限的時間內執行完成，不然就會造成kernel卡死，因此在早期的版本中verifier是拒絕任何loop的存在的，整個程式碼必須是一張DAG(有向無環圖)。不過在kernel 5.3版本開始，verifier允許了有限次數的循環，verifier會透過模擬執行檢查eBPF是不是會在有限次數內在所有可能的分支上走到`bpf_exit`。

接著eBPF程式的大小也存在限制，早期只一個eBPF程式只允許4096個ebpf instruction，在設計比較複雜的eBPF程式上有些捉襟見肘，因此後來在[5.2版](https://github.com/torvalds/linux/commit/c04c0d2b968ac45d6ef020316808ef6c82325a82)這個限制被放寬成1 million個指令，基本上是十分夠用了，也還是能確保ebpf程式在1/10秒內執行完成。

然後程式的stack也存在大小限制，目前限制是512。

當然verifier檢查的項目不只如此，昨天提到的non-GPL licence eBPF程式使用GPL licence的helper function，也會在verifier收到一個`cannot call GPL-restricted function from non-GPL compatible program`的錯誤。

此外verifier也會針對helper function的函數呼叫參數合法性，暫存器數值合法性，或其他無效的使用方式、無效的回傳數值、特定必須的資料結構是否定義、是否非法存取修改數據、無效的instruction參數等等做出檢查以及拒絕存在無法執行到的程式碼。

以此來確保eBPF程式的安全性，具體的verifier可以參考1萬5千行的[原始碼](https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c)

通過verifer的檢查後，eBPF程式會被送到JIT compiler做二次編譯，不過這個部份我們就等到明天再來討論了。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
