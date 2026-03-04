# Day26 - Cgroups

> Day 26\
> 原文：[https://ithelp.ithome.com.tw/articles/10307586](https://ithelp.ithome.com.tw/articles/10307586)\
> 發布日期：2022-10-11

今天開始我們要進入我們BCC專案學習的最後一個實例了，這次我們要看的是`examples/networking/sockmap.py`這隻程式。([原始碼](https://github.com/iovisor/bcc/blob/master/examples/networking/sockmap.py))

不過在開始進入到正題之前，我們要先來聊聊Linux上的一個重要功能cgroups (control groups)，cgroups是Linux kernel內建的一個機制，可以以進程為最小單位，對可使用的CPU、memory、裝置I/O等資源進行限制、分割。

> cgroups目前有v1和v2兩個版本，在分組策略架構上有所差異，這邊介紹只以v1為主

在cgroup的架構內，我們可以針對不同的資源類型進行獨立管理(稱為不同的subsystem或controller) ，一些可能的資源類型和一部份的功能簡介如下

- cpu: 對一定時間週期內，可使用的cpu時間長度限制
- memory: 限制記憶體使用上限以及超出上限時的行為
- blkio: 控制對硬碟等設備的訪問速度上限
- cpuacct: 用來統計目前的CPU使用情況
- devices: 控制可以訪問那些device
- pids: 限制cgroup內可建立的pid數量，也就是進程數量

接著是`hierarchy`，cgroup使用樹狀結構來管理資源，一個`hierarchy`預設會有一個根結點，所有的process (pid都會attach在這個節點上)。

一個`hierarchy`可以對應到零個或多個上述的subsystem，並在一個節點內設置上述的那些限制，那這些限制就會套用到在這個節點內的所有process。

可以在`hierarchy`內建立子節點，那子節點就會預設套用父節點的所有設置，然後可以只針對有興趣的項目作更細緻的調正。

一個process在一棵`hierarchy`只能attach在一個節點上，可以對process設定所在的節點。從process fork出來的process會在同一個節點上，但是搬運process到不同的節點，並不會影響子process。

Linux透過虛擬檔案系統來提供修改調整cgroups的user space介面。  
通常來說介面會被掛載在`/sys/fs/cgroup`這個路徑下。

我們可以透過mount來建立`hierarchy`並把他關連到一個或多個subsystem

``` shell
# 關連到CPU
mkdir /sys/fs/cgroup/cpu
mount -t cgroup -o cpu none /sys/fs/cgroup/cpu
# 關連到CPU和CPUACCT
mkdir /sys/fs/cgroup/cpu,cpuacct
mount -t cgroup -o cpu,cpuacct none /sys/fs/cgroup/cpu,cpuacct
# 不過/sys/fs/cgroup目錄可能會被系統設置為read only，避免隨意變更，而且通常不需要增減hierarchy本身，只是在hierarchy內增減節點管理
```

查看所有目前的hierarchy

``` shell
ls /sys/fs/cgroup/ -l
total 0
dr-xr-xr-x 4 root root  0  十  11 22:50 blkio
lrwxrwxrwx 1 root root 11  十  11 22:50 cpu -> cpu,cpuacct
lrwxrwxrwx 1 root root 11  十  11 22:50 cpuacct -> cpu,cpuacct
dr-xr-xr-x 4 root root  0  十  11 22:50 cpu,cpuacct
dr-xr-xr-x 2 root root  0  十  11 22:50 cpuset
dr-xr-xr-x 4 root root  0  十  11 22:50 devices
dr-xr-xr-x 2 root root  0  十  11 22:50 freezer
dr-xr-xr-x 2 root root  0  十  11 22:50 hugetlb
dr-xr-xr-x 4 root root  0  十  11 22:50 memory
dr-xr-xr-x 2 root root  0  十  11 22:50 misc
lrwxrwxrwx 1 root root 16  十  11 22:50 net_cls -> net_cls,net_prio
dr-xr-xr-x 2 root root  0  十  11 22:50 net_cls,net_prio
lrwxrwxrwx 1 root root 16  十  11 22:50 net_prio -> net_cls,net_prio
dr-xr-xr-x 2 root root  0  十  11 22:50 perf_event
dr-xr-xr-x 4 root root  0  十  11 22:50 pids
dr-xr-xr-x 2 root root  0  十  11 22:50 rdma
dr-xr-xr-x 5 root root  0  十  11 22:50 systemd
dr-xr-xr-x 5 root root  0  十  11 22:50 unified
```

接著查看cpu的根結點

    ls /sys/fs/cgroup/cpu/ -l
    total 0
    -rw-r--r--  1 root root 0  十  11 21:39 cgroup.clone_children
    -rw-r--r--  1 root root 0  十  11 21:39 cgroup.procs
    -r--r--r--  1 root root 0  十  11 21:39 cgroup.sane_behavior
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.stat
    -rw-r--r--  1 root root 0  十  11 21:39 cpuacct.usage
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.usage_all
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.usage_percpu
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.usage_percpu_sys
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.usage_percpu_user
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.usage_sys
    -r--r--r--  1 root root 0  十  11 21:39 cpuacct.usage_user
    -rw-r--r--  1 root root 0  十  11 21:39 cpu.cfs_period_us
    -rw-r--r--  1 root root 0  十  11 21:39 cpu.cfs_quota_us
    -rw-r--r--  1 root root 0  十  11 21:39 cpu.shares
    -r--r--r--  1 root root 0  十  11 21:39 cpu.stat
    drwxr-xr-x  4 root root 0  八  24 14:50 docker
    -rw-r--r--  1 root root 0  十  11 21:39 notify_on_release
    -rw-r--r--  1 root root 0  十  11 21:39 release_agent
    drwxr-xr-x 96 root root 0  十  11 06:05 system.slice
    -rw-r--r--  1 root root 0  十  11 21:39 tasks
    drwxr-xr-x  2 root root 0  十  11 21:31 user.slice

由於前面可以看到cpu被link到cpu,cpuacct，所以可以同時查看到cpu.\*和cpuacct.\*的選項。

透過cpu.cfs_quota_us和cpu.cfs_period_us我們就能控制這個節點上所有process在period內可使用的CPU時間(quota)。

透過`cat tasks`我們可以看到所有attach在這個節點上的pid。

可以看到有三個資料夾`docker`, `system.slice`, `user.slice`，是三個hierarchy上的子節點，我們可以簡單的透過`mkdir`的方式建立子節點。由於這台設備上有跑docker，所以docker會在/sys/fs/cgroup/cpu/docker/目錄下為每個container建立獨立的子節點，透過cgroup的方式限制容器的資源使用量。

``` shell
docker ps --format="{{.ID}}"
90f64cb70ee0
177d1a3920ec

ls /sys/fs/cgroup/cpu/docker -l
total 0
drwxr-xr-x 2 root root 0  八  24 14:50 177d1a3920ec9....
drwxr-xr-x 2 root root 0  八  24 14:50 90f64cb70ee068...
-rw-r--r-- 1 root root 0  十  11 21:39 cgroup.clone_children
-rw-r--r-- 1 root root 0  十  11 21:39 cgroup.procs
...
```

> 在許多發行版上使用systemd來做為核心系統管理程式，也就會透過systemd來管理cgroup，因此在設置kubelet時會建議將cgroup driver從cgroupfs改成systemd，統一由systemd來管理，避免同時有兩個系統在調整cgroup

cgroup v2調整了管理介面的結構，只保留了單一個hierarchy (/sys/fs/cgroup/unified)管理所有的subsystem，因為切出多個hierarchy來管理的方式被認為是不必要且增加系統複雜度的。

到這邊大概介紹完了cgroup，由於這次sockmap.py使用的program type的hook point會在cgroup上，所以趁這個機會詳細了解了一下cgroup。

- 參考文件
  - <https://man7.org/linux/man-pages/man7/cgroups.7.html>
  - <https://medium.com/starbugs/%E7%AC%AC%E4%B8%80%E5%8D%83%E9%9B%B6%E4%B8%80%E7%AF%87%E7%9A%84-cgroups-%E4%BB%8B%E7%B4%B9-a1c5005be88c>
  - <https://blog.csdn.net/qq_46595591/article/details/107634756>

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
