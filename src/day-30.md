# Day30 - eBPF helper function速覽 (下)

> Day 30\
> 原文：[https://ithelp.ithome.com.tw/articles/10308777](https://ithelp.ithome.com.tw/articles/10308777)\
> 發布日期：2022-10-14

接續昨天的內容，今天會介紹網路相關的helper function。由於網路這塊的helper function相對比較雜多，所以有點難以分類，所以只有XDP和LWT有單獨分類出來，其他的tc, socket相關的全部歸在一類。

### XDP 相關

- 於XDP修改封包大小(可以增大或縮小)

  - bpf_xdp_adjust_head
  - bpf_xdp_adjust_tail

- XDP_TX redirect使用

  - bpf_redirect_map

- XDP輸出封包內容到perf event

  - bpf_xdp_output

- 調整`xdp_md->data_meta`

  - bpf_xdp_adjust_meta

- 查詢fid (Forward Information Base, L2)

  - bpf_fib_lookup (也可用在TC)

### LWT 相關

- attach 在routing table
  - 替L3封包進行tunnel header encap
    - bpf_lwt_push_encap
  - 外封包(underlay)內容修改
    - bpf_lwt_seg6_store_bytes
    - bpf_lwt_seg6_adjust_srh
  - 套用IPv6 Segment Routing action決策
    - bpf_lwt_seg6_action

### socket, socket buffer相關

- 用於`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`，修改bind address

  - bpf_bind

- 讀取封包內容

  - bpf_skb_load_bytes
  - bpf_skb_load_bytes_relative

- 修改封包內容，可自動更新chekcsum

  - bpf_skb_store_bytes

- 改寫l3, l4的checksum

  - bpf_l3_csum_replace
  - bpf_l4_csum_replace

- 用於計算check sum，可搭配前兩個replace函數使用

  - bpf_csum_diff

- 取得xfrm (IPsec相關)

  - bpf_skb_get_xfrm_state

- 將封包發到其他的device。後者會複製一分封包。

  - bpf_redirect
  - bpf_clone_redirect

- 取得classid，參考cgroup 的net_cls，使用於TC egress path。

  - bpf_get_cgroup_classid

- 增減vlan header

  - bpf_skb_vlan_push
  - bpf_skb_vlan_pop

- 取得、修改封包的tunnel(ex. GRE)的tunnel key資訊

  - bpf_skb_get_tunnel_key
  - bpf_skb_set_tunnel_key

- 取得、修改封包的tunnel資訊

  - bpf_skb_get_tunnel_opt
  - bpf_skb_set_tunnel_opt

- 取得skb的tclassid欄位，用於clsact TC egress

  - bpf_get_route_realm

- 修改封包 prtocol (ipv4, ipv6)

  - bpf_skb_change_proto

- 修改封包類型 (broadcast, multicast, unitcast..)

  - bpf_skb_change_type

- 搭配`BPF_MAP_TYPE_CGROUP_ARRAY`使用，檢查skb是不是在某個cgroup v2節點的子節點內。

  - bpf_skb_under_cgroup

- 取得skb對應的cgroup id

  - bpf_skb_cgroup_id

- 向上查找skb對應cgroup節點的祖先節點id

  - bpf_sk_ancestor_cgroup_id

- 取得、修改`skb->hash`

  - bpf_get_hash_recalc
  - bpf_set_hash

- 修改封包大小

  - bpf_skb_change_tail

- 用於封包payload存取，具體內容有點難理解 (non-linear data)

  - bpf_skb_pull_data

- 修改`skb->csum`

  - bpf_csum_update

- 修改`skb->csum_level`

  - bpf_csum_level

- 標註`skb->hash`為無效，觸發重算

  - bpf_set_hash_invalid

- 將`skb->sk`轉成所有欄位都可以訪問的版本

  - bpf_sk_fullsock

- 從`skb->sk`取得`struct bpf_tcp_sock`

  - bpf_tcp_sock

- 向tcp-sock對應的方向發一個tcp-ack

  - bpf_tcp_send_ack

- 從`skb->sk`取得`bpf_sock`

  - bpf_get_listener_sock

- 設置`skb->sk`

  - bpf_sk_assign

- 取得bpf_sock對應的cgroupv2 id

  - bpf_sk_cgroup_id

- 取得bpf_sock對應cgroupv2節點的祖先id

  - bpf_sk_ancestor_cgroup_id

- 強制轉型sk成特定的XXX_sock結構

  - bpf_skc_to_tcp6_sock
  - bpf_skc_to_tcp_sock
  - bpf_skc_to_tcp_timewait_sock
  - bpf_skc_to_tcp_request_sock
  - bpf_skc_to_udp6_sock

- 增加packet header區 (headroom) 長度，用於為L3封包直接加上L2的header

  - bpf_skb_change_head

- 幫socket建立一個cookie，作為socket的identifier，用於追蹤

  - bpf_get_socket_cookie(sk_buff)
  - bpf_get_socket_cookie(bpf_sock_addr)
  - bpf_get_socket_cookie(bpf_sock_ops)

- 取得socket的owner UID

  - bpf_get_socket_uid

- 模擬呼叫getsocketopt、setsockopt

  - bpf_getsockopt
  - bpf_setsockopt

- 存取skb的ebpf local storage

  - bpf_sk_storage_get
  - bpf_sk_storage_delete

- 將封包內容輸出到perf event

  - bpf_skb_output

- 修改封包payload大小，可以從L2或L3的角度來看

  - bpf_skb_adjust_room

- 產生、尋找封包對應的`SYN cookie ACK`  
  + bpf_tcp_gen_syncookie  
  + bpf_tcp_check_syncookie

- `BPF_PROG_TYPE_SK_SKB` (ingress方向)

  - 搭配`BPF_MAP_TYPE_SOCKMAP`做socket redierct
    - bpf_sk_redirect_map
    - bpf_sk_redirect_hash
  - 搜尋滿足對應5-tuple的socket
    - bpf_sk_lookup_tcp
    - bpf_skc_lookup_tcp
    - bpf_sk_lookup_udp
  - 釋放上面兩個找到的socket的reference
    - bpf_sk_release

- `BPF_PROG_TYPE_SK_MSG` (egress方向)

  - 搭配`BPF_MAP_TYPE_SOCKMAP`做socket redierct
    - bpf_msg_redirect_map
    - bpf_msg_redirect_hash
  - 替特定長度的內容作verdict (SK_PASS...)，可用於截短封包，優化處理速度 (tc相關的東西不太熟.../)
    - bpf_msg_apply_bytes
  - 跳過接下來某長度的內容不做veridct
    - bpf_msg_cork_bytes
  - 讀寫修改特定長度的資料
    - bpf_msg_pull_data
    - bpf_msg_pop_data
    - bpf_msg_push_data

- 更新`BPF_MAP_TYPE_SOCKMAP`

  - bpf_sock_map_update

- 設置`bpf_sock_ops->bpf_sock_ops_cb_flags`欄位

  - bpf_sock_ops_cb_flags_set

- 更新sockhash

  - bpf_sock_hash_update

- 用於`BPF_PROG_TYPE_SK_REUSEPORT`(將多個程式綁定在同一個port上)

  - sk_select_reuseport

- 用於`BPF_PROG_TYPE_CGROUP_SKB`，設置ECN (Explicit Congestion Notification)

  - bpf_skb_ecn_set_ce

### 結語

到此，我們完成了幾乎所有helper functions的速介，今天同時也是這個系列的第三十天，到了這個系列的尾聲。

很臨時也沒有經驗和準備的參加了ithome鐵人三十天，同時選擇了eBPF這個沒有真正實際接觸過的主題。很開心能夠透過這三十天的時間，對eBPF這個系統有一個初步的認知，並把搜尋和整理後的資料分享給大家，並建立了一個幾乎每天查資料寫文章的習慣。

比較可惜的是如前面所說，並沒有一開始規劃好整個30天的文章框架，再加上是完全沒有接觸過的主題，每天的文章內容分量和知識量比預期能寫的要少許多，介紹基本知識和BCC的天數也完全超出了預期，因此很可惜的沒有能在這個系列裡講到原本要介紹的Cilium CNI。加上對eBPF還有tc系統的不熟悉，因此在許多地方的介紹可能並不是非常清楚或有錯誤，還請大家見諒，還有歡迎提出更正。

這次算是花了30天累積寫文章的經驗，以及除了對eBPF的學習外，還有對Linux kernel souce code還有linux上的一些網路系統概念的學習。

到這邊下台一鞠躬，希望這個系列有幫助到大家!

### 後記

本系列30天鐵人文章整理重新發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)，我的部落格還有其他openstack, terraform, cni相關的文章，有興趣可以來了解交流~!
