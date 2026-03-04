# Day20 - 外傳 - Socket filter 底層探索 (下)

> Day 20\
> 原文：[https://ithelp.ithome.com.tw/articles/10304284](https://ithelp.ithome.com.tw/articles/10304284)\
> 發布日期：2022-10-04

接旭昨天，我們可以更深入的了解一下eBPF對`BPF_ABS`做了什麼事情，在verifier這個神奇的地方搜尋`BPF_ABS`這個instruction，會找到下面這段內容(簡化版)

``` c
/* Implement LD_ABS and LD_IND with a rewrite, if supported by the program type. */
if (BPF_CLASS(insn->code) == BPF_LD &&
    (BPF_MODE(insn->code) == BPF_ABS ||
     BPF_MODE(insn->code) == BPF_IND)) {
    
    cnt = env->ops->gen_ld_abs(insn, insn_buf);
    new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
```

首先執行條件是`BPF_LD`及`BPF_ABS`，我們的code剛好符合這個條件，接著會呼叫`env->ops->gen_ld_abs`，根據原本的instrunction `insn`，生成新的instruction寫入`insn_buf`，接著呼叫`bpf_patch_insn_data`將原本的指令取代為新的指令。

接著我們要找一下`gen_ld_abs`，跟day 11介紹map的情況類似，verifier定義了bpf_verifier_ops 結構，讓不同的program type根據需要，實作bpf_verifier_ops 定義的function來提供不同的功能和行為。

socket filter的定義如下

``` c
const struct bpf_verifier_ops sk_filter_verifier_ops = {
    .get_func_proto     = sk_filter_func_proto,
    .is_valid_access    = sk_filter_is_valid_access,
    .convert_ctx_access = bpf_convert_ctx_access,
    .gen_ld_abs     = bpf_gen_ld_abs,
};
```

所以讓我們看到`bpf_gen_ld_abs` (一樣經過簡化只看我們需要的部分)

``` c
static int bpf_gen_ld_abs(const struct bpf_insn *insn,
              struct bpf_insn *insn_buf)
{
    *insn++ = BPF_MOV64_REG(BPF_REG_2, orig->src_reg);

/* We're guaranteed here that CTX is in R6. */
    *insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_CTX);

    *insn++ = BPF_EMIT_CALL(bpf_skb_load_helper_16_no_cache);
}
```

看到最後一行就很清晰了，最後其實等於調用了內部使用的helper function來存取資料。eBPF也提提供了類似的helper function `bpf_skb_load_bytes`，來提供存取封包內容的功能。

``` c
BPF_CALL_2(bpf_skb_load_helper_16_no_cache, const struct sk_buff *, skb,
       int, offset)
{
    return ____bpf_skb_load_helper_16(skb, skb->data, skb->len - skb->data_len,
                      offset);
}
```

而bpf_skb_load_helper_16_no_cache其實就是直接從`sk_buff->data`的位置取得資料，data是sk_buff用來指到封包開頭的指標。

既然整個指令的本質是從`sk_buff->data`拿取資料，那我們是不是能夠直接從`__sk_buff`裡面拿到資料呢?

在socket program type下program context是`__sk_buff`，他其實本質是對sk_buff的多一層封裝(原因[參見](https://lwn.net/Articles/636647))，在執行的時候，verifier換將其取代回sk_buff，因此\_\_sk_buff等於是sk_buff暴露出來的介面。

    struct __sk_buff {
        ...
        __u32 data;
        __u32 data_end;
        __u32 napi_id;
        ...

參考\_\_sk_buff的定義，`__sk_buff`是有定義將`data`和`data_end`，那我們原始的eBPF程式是不是可以改成

    void *cursor = (void*)(long)(__sk_buff->data);
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet->type == 0x0800)) {
            goto DROP;
    }

如果完成這樣的修改，重新跑一遍`http-parse-simple.py`，你會得到

``` shell
python3 http-parse-simple.py -i eno0
binding socket to 'enp0s3'
bpf: Failed to load program: Permission denied
; int http_filter(struct __sk_buff *skb) {
0: (bf) r6 = r1
; void *cursor = (void*)(long) skb->data;
1: (61) r7 = *(u32 *)(r6 +76)
invalid bpf_context access off=76 size=4
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

Traceback (most recent call last):
  File "http-parse-simple.py", line 69, in <module>
    function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)
  File "/usr/lib/python3/dist-packages/bcc/__init__.py", line 526, in load_func
    raise Exception("Failed to load BPF program %s: %s" %
Exception: Failed to load BPF program b'http_filter': Permission denied
```

可以看到程式碼被verifier拒絕，並拿到了一個`invalid bpf_context access off=76 size=4`的錯誤，表示存取`__sk_buff->data`是非法的。

回去追蹤程式碼的話，會看到在verifier裡面會用`env->ops->is_valid_access`來檢查該存取是否有效，這同樣定義在`bpf_verifier_ops`結構內。

其中socket filter program的實作是

    static bool sk_filter_is_valid_access(int off, int size,
                          enum bpf_access_type type,
                          const struct bpf_prog *prog,
                          struct bpf_insn_access_aux *info)
    {
        switch (off) {
        case bpf_ctx_range(struct __sk_buff, tc_classid):
        case bpf_ctx_range(struct __sk_buff, data):
        case bpf_ctx_range(struct __sk_buff, data_meta):
        case bpf_ctx_range(struct __sk_buff, data_end):
        case bpf_ctx_range_till(struct __sk_buff, family, local_port):
        case bpf_ctx_range(struct __sk_buff, tstamp):
        case bpf_ctx_range(struct __sk_buff, wire_len):
        case bpf_ctx_range(struct __sk_buff, hwtstamp):
            return false;
        }
        ...

可以很直接看到拒絕了data的存取。

從linux kernel的[變更紀錄](https://github.com/torvalds/linux/commit/db58ba45920255e967cc1d62a430cebd634b5046)來推測，data欄位好像本來就不是給socket filter使用的，只是單純因為cls_bpf和socker filter可能共用了這部分的程式碼，因此要額外阻擋這部分的code不讓使用。

最後還有一個沒解決的問題，`u8 *cursor = 0;`，為甚麼空指標經過LLVM編譯後會編譯成對skb的存取還是未知的，看起來像是BCC特別的機制，但是找不太到相關資料，只好保留這個問題。

參考資料

- <https://stackoverflow.com/questions/61702223/bpf-verifier-rejects-code-invalid-bpf-context-access>
- <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
