# Day11 - eBPF基本知識(8) - map (上)

> Day 11\
> 原文：[https://ithelp.ithome.com.tw/articles/10298916](https://ithelp.ithome.com.tw/articles/10298916)\
> 發布日期：2022-09-26

今天我們要介紹eBPF的另外一個重要組件`map`，前一天提到trace_printk只適合用在除錯階段，輸出eBPF的執行資訊到user space，然而我們需要一個可以在正式環境內，提供user space程式和eBPF程式之間雙向數據交換的能力，另外每次觸發eBPF程式都可看作獨立執行eBPF程式，所以也需要在多次呼叫eBPF程式時共享資料的功能。因此eBPF程式引入了`map`。

eBPF map定義了一系列不同的不同的資料結構類型，包含了hash, array, LRU hash, ring buffer, queue等等，另外也提供per-cpu hash, per-cpu array等資料結構，由於每顆CPU可以獲得獨立的map，因此可以減少lock的需求，提高執行效能。所有的map type一樣可以參考[bpf.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h#n880)的`enum bpf_map_type`。

    struct bpf_map_def SEC("maps") map = {  
        .type = BPF_MAP_TYPE_ARRAY,  
        .key_size = sizeof(int),  
        .value_size = sizeof(__u32),  
        .max_entries = 4096,  
    };

首先要先在eBPF程式內定義map的資料結構，在eBPF程式內定義一個map時，基本需要定義四個東西分別是該資料結構的map type, key和value的大小以及資料結構內最多有含多少entry，如果超出max_entries上限則會發生錯誤回傳(-E2BIG)。

eBPF提供了`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`等helper functions來對map資料做操作。lookup的完整定義是`void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)`，透過key去尋找map裡面對應的value，並返回其指標，由於返回的是指標，所以會指向map真實儲存的記憶體，可以直接對其值進行更新。

當然除了幾個基本的helper function外，不同的map type可能會支援更多的操作或功能，例如bpf_skb_under_cgroup是給BPF_MAP_TYPE_CGROUP_ARRAY專用的。

### 原始碼解析

linux kernel定義了[struct bpf_map_ops](https://elixir.bootlin.com/linux/latest/source/include/linux/bpf.h#L64)，來描述map可能會支援的所有功能。

``` c
struct bpf_map_ops {
    /* funcs callable from userspace (via syscall) */
    int (*map_alloc_check)(union bpf_attr *attr);
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_release)(struct bpf_map *map, struct file *map_file);
    void (*map_free)(struct bpf_map *map);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
    void (*map_release_uref)(struct bpf_map *map);
    void *(*map_lookup_elem_sys_only)(struct bpf_map *map, void *key);
    ...
}
```

不同的map再根據需要去實作對應的操作，在[include/linux/bpf_types.h](https://github.com/torvalds/linux/blob/master/include/linux/bpf_types.h)定義。以`BPF_MAP_TYPE_QUEUE`這個map type來說對應到queue_map_ops。

``` c
// kernel/bpf/queue_stack_maps.c

const struct bpf_map_ops queue_map_ops = {
    .map_meta_equal = bpf_map_meta_equal,
    .map_alloc_check = queue_stack_map_alloc_check,
    .map_alloc = queue_stack_map_alloc,
    .map_free = queue_stack_map_free,
    .map_lookup_elem = queue_stack_map_lookup_elem,
    .map_update_elem = queue_stack_map_update_elem,
    .map_delete_elem = queue_stack_map_delete_elem,
    .map_push_elem = queue_stack_map_push_elem,
    .map_pop_elem = queue_map_pop_elem,
    .map_peek_elem = queue_map_peek_elem,
    .map_get_next_key = queue_stack_map_get_next_key,
    .map_btf_name = "bpf_queue_stack",
    .map_btf_id = &queue_map_btf_id,
};
```

當呼叫bpf_map_push_elem時，就會呼叫bpf_map_ops.map_push_elem來調用queue的queue_stack_map_push_elem完成。

而具體每個map支援什麼help function可能就要參考[helper function文件描述](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)

### 使用範例

這邊我們一個特別的使用實例來看

``` c
struct elem {
    int cnt;
    struct bpf_spin_lock lock;
};

struct bpf_map_def SEC("maps") counter = {  
    .type = BPF_MAP_TYPE_ARRAY,  
    .key_size = sizeof(int),  
    .value_size = sizeof(elem),  
    .max_entries = 1,  
};
```

首先我們定義了一個特別的ARRAY map，它的array size只有1，然後value是一個包含u32整數和一個lock的資料結構。

``` c
SEC("kprobe/sys_clone")
int hello_world(void *ctx) {
  u32 key = 0;
  elem *val;
  val = bpf_map_lookup_elem(&counter, &key);
  
  bpf_spin_lock(&val->lock);
  val->cnt++;
  bpf_spin_unlock(&val->lock);

  bpf_trace_printk("sys_clone count: %d", val->cnt);
  
  return 0;
}
```

由於key我們固定是0，透過bpf_map_lookup_elem我們永遠會取得同一筆資料，因此可以簡單看成我們把`counter`當作一個單一的容器來存放cnt變數，並使用lock避免cnt更新時的race condition。

我們將這個程式附加到kprobe/sys_clone，就可以用來統計sys_clone呼叫的次數。

今天我們看到了怎麼透過map保存資料，明天我們會來看看怎麼透過map與user space進行溝通。

- 參考資料  
  <https://vvl.me/2021/02/eBPF-3-eBPF-map/>  
  <https://arthurchiao.art/blog/bpf-advanced-notes-3-zh/>  
  <https://www.ebpf.top/post/bpf_ring_buffer/>  
  <https://blog.csdn.net/M2l0ZgSsVc7r69eFdTj/article/details/108612744>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
