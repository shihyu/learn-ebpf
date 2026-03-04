# Day18 - BCC HTTP filter

> Day 18\
> 原文：[https://ithelp.ithome.com.tw/articles/10303660](https://ithelp.ithome.com.tw/articles/10303660)\
> 發布日期：2022-10-03

我們今天要來看的是bcc的另外一個範例 `examples/networking/http_filter/http-parse-simple.py` ([原始碼](https://github.com/iovisor/bcc/tree/master/examples/networking/http_filter))  
首先一樣先了解一下這支程式的功能，http-parse能夠綁定到一張網路卡上面執行，然後提取經過http流量，將http version, method, uri和status輸出顯示。(當然如果經過tls加密的話是沒辦法的)

執行結果如下

    python http-parse-complete.py 
    GET /pipermail/iovisor-dev/ HTTP/1.1
    HTTP/1.1 200 OK
    GET /favicon.ico HTTP/1.1
    HTTP/1.1 404 Not Found
    GET /pipermail/iovisor-dev/2016-January/thread.html HTTP/1.1
    HTTP/1.1 200 OK
    GET /pipermail/iovisor-dev/2016-January/000046.html HTTP/1.1
    HTTP/1.1 200 OK

前兩天介紹的tcpconnect使用的是`BPF_PROG_TYPE_KPROBE`這個program type，透過kprobe/kretprobe機制在kernel function被呼叫和回傳的時候執行。

今天使用的是`BPF_PROG_TYPE_SOCKET_FILTER`，socket filter 可以對進出socket的封包進行截斷或過濾。特別注意這邊如果會需要擷取封包(長度不等於原始封包長度)則會觸發對封包進行複製，然後修改封包大小。

socket filter program會在socket層被呼叫(在net/core/sock.c的sock_queue_rcv_skb被呼叫)，並傳入[\_sk_buff結構](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L5745)取得socket上下文及封包的內容。

透過回傳的數值來決定如何處理該封包，如果回傳的數值大於等於封包長度，等價於保留完整封包，如果長度小於封包長度，則截斷只保留回傳數值長度的封包。其中兩個特例是回傳0和-1。回傳0等價解取一個長度為0的封包，也就是直接丟棄該封包。回傳-1時，由於封包長度是無號整數，-1等價於整數的最大數值，因此保證保留整個完整的封包。

另外一個關鍵技術是raw socket，我們可以將raw socket監聽某個網路介面上所有進出封包。

因此整個程式的執行方式是這樣的，在目標網路卡上開啟一個raw socket，透過eBPF程式過濾掉所有非http的封包，只保留http封包送出到raw socket，userspace client接收到封包時，可以直接解析封包欄位提取出http封包資訊。

在這次的程式中eBPF c code直接寫在一個獨立的http-parse-simple.c檔案中。

這次的ebpf程式很簡單只有單一個函數`http_filter`，作為socket filter的進度點。

``` c
int http_filter(struct __sk_buff *skb) {

    u8 *cursor = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    //filter IP packets (ethernet type = 0x0800)
    if (!(ethernet->type == 0x0800)) {
        goto DROP;
    }
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    //drop the packet returning 0
    DROP:
    return 0;
...
```

相信很多人跟我一樣第一眼看到這個程式會覺得非常疑惑，首先看到的是`cursor`和`cursor_advance`這兩個東西，從ip那行大概可以猜的出來，cursor是對封包內容存取位置的指標，cursor_advance會輸出當前cursor的位置，然後將cursor向後移動第二個參數的長度。  
由於我們要分析的是http封包，所以他的ether type勢必得是0x0800 (IP)，所以對於不滿足的封包，我們直接goto 到 drop，return 0。表示我們要擷取一個長度為0的封包等價於丟棄該封包。

在bcc的[helpers.h](https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h) 輔助函數標頭檔裡面可以看到cursor_advane的定義。

    // packet parsing state machine helpers
    #define cursor_advance(_cursor, _len) \
      ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

果然符合我們的預期，先將原先cursor指標的數值保留起來，將cursor向後移動len後回傳原始數值。

後面的程式碼其實就很簡單，首先一路解析封包確保他是一個ip/tcp/http封包、封包長度夠長塞的下一個有效的http封包內容

``` c
payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
...
unsigned long p[7];
int i = 0;
for (i = 0; i < 7; i++) {
    p[i] = load_byte(skb, payload_offset + i);
}
```

接著將http packet的前7個byte讀出來，load_byte同樣是定義在[helpers.h](https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h)

    unsigned long long load_byte(void *skb,
        unsigned long long off) asm("llvm.bpf.load.byte");

他會直接轉譯成BPF_LD_ABS，從payload_offset位置開始讀一個byte出來，payload_offset，是前面算出來從ethernet header開始到http payload的位移。

``` c
//HTTP
if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
    goto KEEP;
}
//GET
if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
    goto KEEP;
}
...
//no HTTP match
goto DROP;

//keep the packet and send it to userspace returning -1
KEEP:
return -1;
```

接著檢查如果封包屬於HTTP (以HTTP, GET, POST, PUT, DELETE HEAD...開頭)，就會跳到keep，保留整個完整的封包送到userspace client program。

    GET /favicon.ico HTTP/1.1
    HTTP/1.1 200 OK

HTTP request會以method開頭、response會以HTTP開頭，所以需要查找這些字樣開頭的封包。

接著我們很快速的來看一下python程式碼的部分。

``` python
bpf = BPF(src_file = "http-parse-simple.c",debug = 0)
function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_http_filter, interface)
socket_fd = function_http_filter.sock
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
sock.setblocking(True)
```

首先我們一樣透過BPF物件完成bpf程式碼的編譯，不一樣的是是這邊直接指定src_file從檔案讀取。  
接著透過load_func，指定socket filter這個program type type和http_filter這個入口函數，並載入ebpf bytecode到kernel  
接著透過bcc提供的attach_raw_socket API在interface上建立row socket並將socket filter program attach上去。  
接著從`function_http_filter.sock`取得raw socket的file descripter並封裝成python的socket物件。  
由於後面需要socket是阻塞的，但是attach_raw_socket建立出來的socket是非阻塞的，所以這邊透過`sock.setblocking(True)`阻塞socket

    while 1:
      #retrieve raw packet from socket
      packet_str = os.read(socket_fd,2048)
      packet_bytearray = bytearray(packet_str)
      ...
      for i in range (payload_offset,len(packet_bytearray)-1):
        if (packet_bytearray[i]== 0x0A): # \n
          if (packet_bytearray[i-1] == 0x0D): \r
            break # 遇到http的換行\r\n則結束
        print ("%c" % chr(packet_bytearray[i]), end = "")

後面的程式碼其實就和ebpf的部分大同小異，從socket讀取封包內容、解析到http payload後，將http payload的第一行輸出出來。

到此我們就完成了`http-parse-simple`的解析。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
