# Day12 - eBPF基本知識(9) - map(下)

> Day 12\
> 原文：[https://ithelp.ithome.com.tw/articles/10299791](https://ithelp.ithome.com.tw/articles/10299791)\
> 發布日期：2022-09-27

接續前面的內容，今天我們要來研究怎麼透過`map`與user space的程式溝通。

和其他eBPF的操作一樣，我們透過`bpf`的system call去與kernel進行溝通。跟helper fuction 類似，bpf systemcall 提供了`BPF_MAP_LOOKUP_ELEM`, `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`等參數來提供搜尋、更新、刪除map數值的方法。另外為了減少system call的開銷，也提供`BPF_MAP_LOOKUP_BATCH`, `BPF_MAP_LOOKUP_AND_DELETE_BATCH`, `BPF_MAP_UPDATE_BATCH`, `BPF_MAP_DELETE_BATCH`等方法來在單次system call內完成多次map操作。

必要要注意的是map並不是eBPF program的附屬品，在eBPF虛擬機內，map和program一樣是獨立的物件，每個map有自己的refcnt和生命週期，eBPF程式的生命週期和map不一定是統一的。

### map載入流程

在透過函式庫將eBPF程式載入kernel時，先做的其實是建立map，對每張map會呼叫`bpf system call`的BPF_MAP_CREATE，並帶入map type, key size, value size, max entries, flags等資訊來建立map，建立完成後會返回map對應的fire descripter。

接著函數庫會修改編譯過的ebpf bytecode裡面參考到map變數的地方(例如lookup等helper function的參數部分)，將原先流空的map地址修改成map對應的file descripter。

接著一樣呼叫`bpf` BPF_PROG_LOAD來載入eBPF bytecode，在載入過程中，verifier會呼叫到replace_map_fd_with_map_ptr函數，將bytecode裡面map的file descripter在替換成map的實際地址。

### Map 持久化

如昨天所述，map在eBPF虛擬機內和prog同等是獨立的存在，並且具有自己的refcnt，因此和prog一樣，我們可以透過`bpf` BPF_OBJ_PIN將map釘到BPFFS的`/sys/fs/bpf/`路徑下，其他程式就一樣能透過open file的方式取得map的file descripter，將map載入到其他的eBPF程式內，達成了多個eBPF程式share同一個map的效果。

- 參考資料  
  <https://www.ebpf.top/post/map_internal/>  
  <https://davidlovezoe.club/wordpress/archives/1044>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
