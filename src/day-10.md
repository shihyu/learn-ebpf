# Day10 - eBPF基本知識(7) - debug tracing

> Day 10\
> 原文：[https://ithelp.ithome.com.tw/articles/10298531](https://ithelp.ithome.com.tw/articles/10298531)\
> 發布日期：2022-09-25

在將eBPF程式載入kernel工作後，我們勢必需要一些手段來與eBPF程式做溝通，一方面我們需要輸出偵錯訊息，來對eBPF程式debug，一方面我們可能會希望能夠實時透過eBPF程式取得kernel的某些資訊又或著動態調整eBPF程式的執行規則。

如果只是需要eBPF程式單方面的輸出訊息，讓我們可以偵錯，可以使用比較簡單的手段。eBPF有提供一個helper function `long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)`，可以輸入一個格式化字串`fmt`，及最多三個變數(參數個數的限制)。輸出結果會被輸出到`/sys/kernel/debug/tracing/trace_pipe`中。.

可以透過指令查看輸出結果:

    sudo cat /sys/kernel/debug/tracing/trace_pipe

輸出的格式如下:

       telnet-470   [001] .N.. 419421.045894: 0x00000001: <formatted msg>

- 首先是process name `telnet`，然後是PID 470。
- 接續的001是指當前執行的CPU編號。
- .N..的每個字元對應到一個參數
  - irqs 中斷是否啟用
  - `TIF_NEED_RESCHED`和`PREEMPT_NEED_RESCHED`是否設置 (用於kernel process scheduling)
  - 硬中断/軟中断是否發生中
  - level of preempt_disabled
- 419421.045894 時間
- 0x00000001: eBPF內部的指令暫存器數值

雖然trace_printk可以接收格式化字串，但是支援的格式字元比較少，只支援`%d, %i, %u, %x, %ld, %li, %lu, %lx, %lld, %lli, %llu, %llx, %p, %s`。

另外有一個bpf_printk巨集，會使用sizeof(fmt)幫忙填上第二個fmt_size。因此使用bpf_printk可以省略fmt_size。

在比較新的版本提供了bpf_snprintf和bpf_seq_printf兩個新的print函數，前者是把資料寫入預先建立好的buffer內，後者可以寫入在特定program type下可以取得的seg_file，兩者皆用陣列存放後面的參數列，因此可以打破helper funtion 5個參數的限制。

最後要特別注意的是使用trace_printk會大幅拖慢eBPF程式的執行效率，所以trace_printk只適用於開發時用來debug使用，不適用於正式環境當中。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
