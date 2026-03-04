# Day1 - 前言

> Day 01\
> 原文：[https://ithelp.ithome.com.tw/articles/10292014](https://ithelp.ithome.com.tw/articles/10292014)\
> 發布日期：2022-09-16

## 起源

今年七月底參加COSCUP的時候，在kubernetes的相關議程一直聽到eBPF這個東西，後來參加LINE x KCD Taiwan Meetup \#49，也再次討論了ebpf如何透過Cilium CNI這個專案在k8s裡面發揚光大。雖然聽到eBPF這個東西也已經有好一段時間了，但是一直沒有找機會深入了解和學習使用eBPF。剛好有朋友問我要不要寫鐵人賽，因此正好趁著這個機會好好學習eBPF。

因此本系列文章會是我的eBPF學習筆記，希望能透過這個機會達成有效的學習紀錄，也希望這份整理能夠幫助到其他想接觸eBPF的人。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/posts/Learn-eBPF-Serial-1-Abstract-and-Background/)，我的部落格還有其他openstack, terraform, cni相關的文章，有興趣可以來了解交流~!

## 介紹

本次的30天挑戰預計包含幾個部分

- eBPF的基礎概念與歷史
- 實際的eBPF開發教學
- 更多著墨在XDP、TC、Socket網路相關的幾個eBPF的開發和探索，分析相關專案原始碼
- 有機會的話，可以了解一下cilium CNI和他的eBPF

由於這系列文章算是我的學習筆記，因此會更偏向從應用的角度來探討eBPF和學習開發，並且內容只是初步的規劃，可能會隨著學習歷程做改變。

如果內容有錯誤，還懇請大家協助更正。

以上是前言的部分，從Day2開始就會進入正題了!
