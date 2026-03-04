# Day9 - eBPF基本知識(6) - Helper Funtions

> Day 09\
> 原文：[https://ithelp.ithome.com.tw/articles/10297659](https://ithelp.ithome.com.tw/articles/10297659)\
> 發布日期：2022-09-24

之前在介紹eBPF的GPL授權的時候，有提到eBPF helper function這個東西，今天我們來比較仔細的介紹一下。

之前提到eBPF程式是在eBPF虛擬機內執行，由於eBPF程式會嵌入kernel內，在kernel space執行，所以為了安全性考量我們不能讓eBPF程式任意的存取和修改kernel記憶體和呼叫kernel函數，因此eBPF的解決方案是提供了一系列的API，讓eBPF程式只能夠過限定的API去與kernel溝通，因此可以讓eBPF程式對kernel的操作限制在一個可控的範圍，也可以透過verifier和API後面的實作去確保API呼叫的有效和安全性。

在eBPF裡這一系列的API就稱之為eBPF helper funtions。

另外不同的對於eBPF program type的eBPF程式，由於他們執行的時機點和在kernel的位置不同，因此他們能夠取得的kernel資訊也就不同，他們可以呼叫執行的helper funtions也就不同。具體每個不同program type可以執行的helper function可以參考bcc的[文件](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#program-types)

下面列幾舉個所有program type都可以呼叫的helper function

- u64 bpf_ktime_get_ns(void)
  - 取得從開機開始到現在的時間，單位是奈秒
- u32 bpf_get_prandom_u32(void)
  - 取得一個random number

接著我們舉例在BPF_PROG_TYPE_SOCKET_FILTER下才能使用的helper function

- long bpf_skb_load_bytes(const void \*skb, u32 offset, void \*to, u32 len)
  - 由於socket filter的功能就是對socket的流量做過濾，因此我們可以透過skb_load_bytes來取得socket傳輸的封包內容

完整的helper function列表還有每個函數具體的定義以及使用說明描述可以在[bpf.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)查找到。

另外特別要注意的是受限於eBPF虛擬機的限制，eBPF helper function的參數數量最多只可以有五個，在使用不定參數長度的參數時，最多也只能有5個參數(特別是指明天會提到的trace_printk。

因此雖然eBPF非常強大能夠非常方便的動態對kernel做修改，但為了安全，他可以執行的操作是訂定在一個非常嚴格的框架上的，在開發時需要熟習整個框架的限制和可利用的API資源。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
