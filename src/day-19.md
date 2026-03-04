# Day19 - 外傳 - Socket filter 底層摸索 (上)

> Day 19\
> 原文：[https://ithelp.ithome.com.tw/articles/10304220](https://ithelp.ithome.com.tw/articles/10304220)\
> 發布日期：2022-10-04

前一天我們介紹了http-parse-simple，他利用了socket filter的eBPF program來過濾http封包，然而在解析的過程中保留了兩個疑點。

1.  cursor指標數值為0，但是可以存取到封包的內容。

``` c
u8 *cursor = 0;
struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
if (!(ethernet->type == 0x0800)) {
        goto DROP;
}
```

2.  特別的load_bytes函數呼叫，來取得封包內容

<!-- -->

    load_byte(skb, payload_offset + i);

首先雖然ebpf使用c來編寫，但是經由LLVM編譯後會轉換成eBPF bytecode，在進入kernel後會再經過verifier的修改。(經過這次的探索，可以理解verifier雖然叫做verifier，但是他的功能確包羅萬象，對eBPF架構來說非常重要)

為了理解這段eBPF code後面發生了什麼事，我們先查看LLVM編譯出來的eBPF bytecode。

在BCC編譯時，我們可以透過`debug`這個參數取得編譯過程中的資訊，當然也包含取得LLVM編譯出來的eBPF bytecode，可以使用的debug選項如下

``` python
# Debug flags

# Debug output compiled LLVM IR.
DEBUG_LLVM_IR = 0x1
# Debug output loaded BPF bytecode and register state on branches.
DEBUG_BPF = 0x2
# Debug output pre-processor result.
DEBUG_PREPROCESSOR = 0x4
# Debug output ASM instructions embedded with source.
DEBUG_SOURCE = 0x8
# Debug output register state on all instructions in addition to DEBUG_BPF.
DEBUG_BPF_REGISTER_STATE = 0x10
# Debug BTF.
DEBUG_BTF = 0x20
```

透過`BPF(src='simple-http-parse.c', debug=DEBUG_PREPROCESSOR)`，我們可以看到上面的code被LLVM重新解釋為

``` c
void *cursor = 0;

struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

//filter IP packets (ethernet type = 0x0800)
if (!(bpf_dext_pkt(skb, (u64)ethernet+12, 0, 16) == 0x0800)) {
    goto DROP;
}
```

因此cursor在這邊的用途真的只是計算offset。  
bpf_dext_pkt在bcc的[helper.h](https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h)有所定義

``` c
u64 bpf_dext_pkt(void *pkt, u64 off, u64 bofs, u64 bsz) {
  if (bofs == 0 && bsz == 8) {
    return load_byte(pkt, off);
  } else if (bofs + bsz <= 8) {
    return load_byte(pkt, off) >> (8 - (bofs + bsz))  &  MASK(bsz);
  } else if (bofs == 0 && bsz == 16) {
     return load_half(pkt, off);
  ... 
```

可以看到他是根據參數大小和類型去正確呼叫load_byte, load_half, load_dword系列函數，所以其實他做的事情與我們感興趣的第二段code `load_byte(skb, payload_offset + i);`是一致的。

接著我們使用`BPF(src='simple-http-parse.c', debug=DEBUG_SOURCE)`查看編譯出來的eBPF binary code。

``` c
; int http_filter(struct __sk_buff *skb) { // Line  27
   0:   bf 16 00 00 00 00 00 00 r6 = r1
   1:   28 00 00 00 0c 00 00 00 r0 = *(u16 *)skb[12]
; if (!(bpf_dext_pkt(skb, (u64)ethernet+12, 0, 16) == 0x0800)) { // Line  34
   2:   55 00 5c 00 00 08 00 00 if r0 != 2048 goto +92
```

其中r0, r1, r6是eBPF的register，我們這邊只關注第1行`r0 = *(u16 *)skb[12]`，這行是從skb的第12個byte拿取資料出來，剛好對應到bpf_dext_pkt。

根據ebpf instruction set的定義，第一個byte 28 (0010 1000)是op code。  
最後3個bit 000是op code的種類。這邊的0x00對應到`BPF_LD` (non-standard load operations)

\|3 bits (MSB) \| 2 bits\|3 bits (LSB)\|  
\|------------ \|-----‐------\|-----‐------\|  
\| mode \| size \| instruction class\|

在`BPF_LD`這個分類內，size bits 01剛好對應到`BPF_H` (half word (2 bytes))  
最前面的3個bit 000 代表`BPF_ABS`(legacy BPF packet access)。

到這邊我們就理解它是怎麼運作了了，eBPF定義了`BPF_ABS`來代表對封包的存取操作，LLVM在編譯的時會將對skb的load_byte轉譯成對應的instruction。

參考資料

- <https://www.kernel.org/doc/html/v5.17/bpf/instruction-set.html>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
