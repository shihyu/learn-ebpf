# Day5 - eBPF基本知識(2) - 如何撰寫

> Day 05\
> 原文：[https://ithelp.ithome.com.tw/articles/10294534](https://ithelp.ithome.com.tw/articles/10294534)\
> 發布日期：2022-09-20

從昨天最後的範例可以看到一個eBPF程式其實一個c語言格式的程式碼

``` c
int xdp_prog_simple(struct xdp_md *ctx)
{
    return XDP_DROP;
}
```

eBPF程式碼要被編譯成eBPF虛擬機的bytecode才能夠執行。  
以XDP為例，最底層的做法是直接使用LLVM之類的工具直接編譯這段eBPF程式碼。  
首先需要補齊使用LLVM編譯時，需要的header file和資訊。

``` c
#include <uapi/linux/bpf.h>

SEC("xdp_prog")
int  xdp_program(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
```

接著使用LLVM編譯成ELF格式文件

``` shell
clang -c -target bpf xdp.c -o xdp.o
```

然後使用`bpf` system call將bytecode載入到kernal的eBPF虛擬機內，並取得對應的file descriptor。最後透過netlink socket發送一個`NLA_F_NESTED | 43`訊息來把interface index與ebpf程式的file descriptor綁定。就能夠讓eBPF程式在對應的interface封包處理過程中被呼叫。

iproute2有實作載入eBPF的功能，因此可以透過下指令

    ip link set dev eth1 xdp xdp.o

可能會注意在程式碼的最後一行。特別標註了GPL licence。由於eBPF程式會嵌入到kernel，與kernel緊密的一起執行(共用address space、權限等)，在判斷獨立程式的邊界時，eBPF程式和相關的kernel組件會被視為一體，因此eBPF程式會受到相關的licence限制。  
而這邊提到的內核組件指的是eBPF helper function。後面會詳細介紹helper function是eBPF程式與kernel溝通的橋梁，由於eBPF程式是在eBPF虛擬機內執行，因此如果要取得kernel的額外資訊或改變kernel的行為，必須透過虛擬機提供的helper function接口。  
一部份的helper function基於GPL授權，因此當eBPF程式使用了GPL授權的helper function就必須標示為GPL授權，否則將eBPF程式載入到kernel時，會直接被kernel拒絕。

直接使用最底層的方法開發相對來說是不方便和困難的，不同program type的載入方式可能還完全不一樣，因此許多抽象的框架和SDK被發出來。雖然還是需要編寫eBPF的c code，但是編譯、載入、溝通等工作被包在SDK裡面，可以方便的直接使用。

這邊舉例BPF Compiler Collection (BCC)這套工具，BCC將eBPF的編譯和載入動作包裝成了python的API，因此能夠簡單的完成eBPF的編譯和執行。

``` python
from bcc import BPF
import time

b = BPF(text = """
#include <uapi/linux/bpf.h>
int xdp_prog1(struct xdp_md *ctx)
{
    return XDP_DROP;
}
""")
fn = b.load_func("xdp_prog1", BPF.XDP)
b.attach_xdp("wlp2s0", fn, 0)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
    
b.remove_xdp("wlp2s0", 0)
```

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
