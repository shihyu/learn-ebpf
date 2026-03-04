# Day29 - eBPF helper function速覽 (上)

> Day 29\
> 原文：[https://ithelp.ithome.com.tw/articles/10308306](https://ithelp.ithome.com.tw/articles/10308306)\
> 發布日期：2022-10-14

很快的，這次的鐵人競賽就到尾聲了。  
在eBPF程式裡面要與kernel交互很重要的是helper function，因此在最後的兩天時間，我們要把所有的helper function速覽過一遍。這邊介紹以bpf-helper的[man文件](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)的內容為主，部分的helper function可能因為文件更新而有遺漏。

接下來的介紹會稍微對helper function做一定程度的分類，但是具體不同的eBPF program type 支援那些helper function可能還是要根據[bcc文件](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)、每個helper function對應的commit資訊等查詢。

今天會先介紹非網路相關的helper function，明天則會介紹網路相關的部分。

### eBPF map操作類

- array, map類型map的操作函數，對應到查詢、插入或更新、刪除map內的元素。其中update可以透過flag (`BPF_NOEXIST`, `BPF_EXIST`, `BPF_ANY`)決定key是不是不能先存在或一定要存在於map內。

  - bpf_map_lookup_elem
  - bpf_map_update_elem
  - bpf_map_delete_elem

- 用於stack, queue類型map的操作函數。

  - bpf_map_peek_elem
  - bpf_map_pop_elem
  - bpf_map_push_elem

- 用於ringbuff的操作函數 (改進原本perf event map的問題)

  - bpf_ringbuf_output
  - bpf_ringbuf_reserve
  - bpf_ringbuf_submit
  - bpf_ringbuf_discard
  - bpf_ringbuf_query

### 通用函數

- 生成隨機數

  - get_prandom_u32

- `atol`, `atoul`

  - bpf_strtol
  - bpf_strtoul

- 取得當前執行eBPF程式的(SMP) processor ID。由於eBPF是no preemption的所以在整個執行過程中processor id不會變。

  - bpf_get_smp_processor_id

- 取得當前NUMA (Non-uniform memory access) 的node id。受於匯流排限制，CPU核心可以比較快存取同節點上的memory，透過node id區分。通常是當attach的socket有啟用`SO_ATTACH_REUSEPORT_EBPF`選項時會用到。

  - bpf_get_numa_node_id

- 搭配`BPF_MAP_TYPE_PROG_ARRAY` map去執行tail call。

  - bpf_tail_call

- 取得開機到當下經過的時間，單位是ns，差別在於後者會多包含suspend(暫停)的時間

  - bpf_ktime_get_ns
  - bpf_ktime_get_boot_ns

- 取得jiffies64

  - bpf_jiffies64

- 將字串訊息發送到 /sys/kernel/debug/tracing/trace ，主要用於開發除錯

  - bpf_trace_printk

- 寫入seq_file

  - bpf_seq_write
  - bpf_seq_printf

- 搭配`struct bpf_spin_lock`提供一個給`BPF_MAP_TYPE_HASH`和`BPF_MAP_TYPE_ARRAY`(目前只支援這兩著)裡面value使用的lock，由於一個map裡面只能有一個spin_lock，所以通常是使用把之前提過，整個map固定只有一個元素，把整個map當作一個global variable的用法

  - bpf_spin_lock
  - bpf_spin_unlock

- 搭配`BPF_MAP_TYPE_PERF_EVENT_ARRAY`使用，傳輸資料到user space

  - bpf_perf_event_output

### Tracing 相關 (kprobe, tracepoint, perf event)

- 取得當前的tgid, uid, gid, command name, task structure

  - bpf_get_current_pid_tgid
  - bpf_get_current_uid_gid
  - bpf_get_current_comm
  - bpf_get_current_task

- 發signal到當前(process, thread)

  - bpf_send_signal
  - bpf_send_signal_thread

- 用於讀取記憶體資料、字串及寫入記憶體。帶user的版本用於user space memory，其餘用於kernel space memory。

  - bpf_probe_read (通常使用後倆著)
  - bpf_probe_read_user
  - bpf_probe_read_kernel
  - bpf_probe_read_str (通常使用後倆著)
  - bpf_probe_read_user_str
  - bpf_probe_read_kernel_str
  - bpf_probe_write_user

- 搭配`BPF_MAP_TYPE_STACK_TRACE`使用，取得一個stack address hash過的stack id

  - bpf_get_stackid

- 取得userspace或kernel space的stack資料

  - bpf_get_stack
  - bpf_get_task_stack

- 搭配`BPF_MAP_TYPE_PERF_EVENT_ARRAY`取得perf-event counter的讀數

  - bpf_perf_event_read
  - bpf_perf_event_read_value (建議使用)

- 用於`BPF_PROG_TYPE_PERF_EVENT` 取得struct perf_branch_entry

  - bpf_read_branch_records

- 搭配`BPF_MAP_TYPE_CGROUP_ARRAY`使用，檢查是否在某個cgroup v2節點內

  - bpf_current_task_under_cgroup

- 查看當前上下文的cgroup節點的祖先節點id

  - bpf_get_current_ancestor_cgroup_id

- 取得當前上下文對應的cgroup id

  - bpf_get_current_cgroup_id

- 用於kprobe，修改函數回傳值

  - bpf_override_return

### Cgroup 相關

- 取得一個當前network namespace對應的cookie (identifer)

  - bpf_get_netns_cookie

- 取得local storage的指標 (cgroup相關可使用的一個儲存區)

  - bpf_get_local_storage

- 用於`BPF_PROG_TYPE_CGROUP_SYSCTL`

  - 取得、更新sysctl資訊
    - bpf_sysctl_get_name
    - bpf_sysctl_get_current_value
    - bpf_sysctl_get_new_value
    - bpf_sysctl_set_new_value

### 其他類別

- LIRC 紅外線收發相關 (BPF_PROG_TYPE_LIRC_MODE2)
  - bpf_rc_repeat
  - bpf_rc_keydown
  - bpf_rc_pointer_rel

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
