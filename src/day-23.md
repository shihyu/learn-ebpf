# Day23 - TC概念

> Day 23\
> 原文：[https://ithelp.ithome.com.tw/articles/10306218](https://ithelp.ithome.com.tw/articles/10306218)\
> 發布日期：2022-10-08

接續前兩天的主題`XDP`，今天我們要繼續來聊聊eBPF在linux netowrk data path上的另外一個進入點`tc`。

首先我們要先聊聊`tc`是什麼東西。Traffic Control (tc) 是linux kernel 網路系統裡面和netfilter/iptables 同等重要的一個組件。不過netfilter主要著重在packet mangling(封包修改)和filter(過濾)。而tc的重點是在調控流量，提供限速、整形等功能。

tc的工作時機點分成`ingress tc`和`egress tc`，以`ingress tc`來說，他發生在skb allocation之後，進入netfilter之前。`ingress tc`主要用於輸入流量控制，`egress tc`則用於流量優先級、QoS的功能。在傳統使用上，tc更主要是用在`egress tc`，`ingress tc`本身有比較大的功能限制。

在`tc`裡面有三個主要的概念，`qdisc`、`class` 和 `filter(classifier)`。

tc的基礎是queue，封包要進出主機時，會先進入queue，根據特定的策略重新排序、刪除、延遲後再交給網卡送出，或netfilter等系統收入。

`qdisc`是套用在這個queue上面的策略規則。下列舉例一部份:

- 最基本的策略規則是pfifo，就是一個簡單的FIFO queue，只能設定queue的可儲存的封包大小和封包個數。
- 更進階的如pfifo_fast，會根據ip封包內的`ToS`欄位將封包分成三個優先度，每個優先度內是走FIFO規則，但是會優先清空高優先度的封包。
- [sfq](https://man7.org/linux/man-pages/man8/tc-sfq.8.html)則是會根據tcp/udp/ip欄位hash的結果區分出不同的連線，將不同連線的封包放入獨立的bucket內，然後bucket間使用輪尋的方式，來讓不同連線均等的輸出。
- ingress是專門用在ingress tc的qdisc  
  上面的qdisc都歸為classless QDisc，因為我們不能透過自定義的方式對流量進行分類，提供不同的策略。

與classless相反的是classful qdisc，在classful qdisc內，我們可以以定義出多個`class`，針對不同的class設定不同的限速策略等規則。也可以將多個class附屬在另外一個class下，讓子class共用一個父class的最大總限速規則，但是子分類又獨立有限速規則等等。

而要對流量進行分類就會用到`filter`,對於某個qdisc(classless/classful皆可)或著父class上的封包，如果滿足filter的條件，就可以把封包歸到某個class上。  
除了歸類到某個class上，filter也可以設置為執行某個action，包括丟棄封包、複製封包流量到另外一個網路介面上之類的...

對於qdisc和class在建立時需指定或自動分配一個在網卡上唯一的handle作為識別id，格式是`<major>:<minor>`(數字)，對於qdisc來說只有major的部分`<major>:`，對class來說major必須與對應qdisc相同。

另外在egress pipeline可以有多個qdisc，其中一個作為root，其他的藉由filter從root qdisc dispatch過去，所以需要有major這個欄位。

在linux上面主要透過`tc`這個指令來設置`qdisc`、`class` 和 `filter`。

``` shell
# 添加eth0 egress的root qdisc，類型是htb，後面是htb的參數
tc qdisc add dev enp0s3 root handle 1: htb default 30
# 添加eth的ingress qdisc
tc qdisc add dev enp0s3 ingress

# 設置一個class，速度上下限都是20mbps，附屬於eth0的root qdisc(1:)下
tc class add dev enp0s3 partent 1: classid 1:1 htb rate 20mbit ceil 20mbit

# 當封包為ip, dst port 80時分類到上述分類
tc filter add dev enp0s3 protocol ip parent 1: prio 1 u32 match ip dport 80 0xffff flowid 1:1
```

``` shell
# 查看egress filter
tc filter show dev eth0

# 查看ingress filter
tc filter show dev eth0 ingress
```

到此我們完成了tc的基本介紹，明天就要進入到eBPF tc的部分了

參考資料

- <https://tldp.org/HOWTO/Adv-Routing-HOWTO/lartc.qdisc.filters.html>
- <https://man7.org/linux/man-pages/man8/tc.8.html>
- <https://arthurchiao.art/blog/lartc-qdisc-zh/>
- <https://cloud.tencent.com/developer/article/1409664>
- <https://developer.aliyun.com/article/4000>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
