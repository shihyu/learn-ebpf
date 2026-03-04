# Day15 - BCC 安裝

> Day 15\
> 原文：[https://ithelp.ithome.com.tw/articles/10301922](https://ithelp.ithome.com.tw/articles/10301922)\
> 發布日期：2022-09-30

首先bcc的安裝大概有幾種方式

- 透過各大發行板的套件管理工具安裝
- 直接使用原始碼編譯安裝
- 透過docker image執行  
  對於前兩著，bcc官方的文件列舉了需多發行版的[安裝方式](https://github.com/iovisor/bcc/blob/master/INSTALL.md)，所以可以很容易地照著官方文件安裝。以ubuntu來說，可以透過Universe或iovisor的repo安裝。

<!-- -->

    # use Universe
    # add-apt-repository universe 

    # iovisor
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
    echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main" | sudo tee /etc/apt/sources.list.d/iovisor.list

    sudo apt-get update
    sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)

然而必須要注意的是，目前iovisor和universe上面的bcc套件本的都比較陳舊，甚至沒有20.04和22.04對應的安裝源，因此透過apt安裝可能會出現版本不支援或安裝後連範例都跑不起來的問題。

因此特別建議透過原始碼來安裝會是比較穩妥的方式。一樣在bcc的的[安裝文檔](https://github.com/iovisor/bcc/blob/master/INSTALL.md) 詳細列舉了在各個發行版本的各個版本下，要怎麼去安裝相依套件，然後編譯安裝bcc。

    sudo apt install -y bison build-essential cmake flex git libedit-dev \
      libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils

    git clone https://github.com/iovisor/bcc.git
    mkdir bcc/build; cd bcc/build
    cmake ..
    make
    sudo make install
    cmake -DPYTHON_CMD=python3 .. # build python3 binding
    pushd src/python/
    make
    sudo make install
    popd

這邊同樣以ubuntu舉例，首先因為BCC後端還是使用LLVM，因此需要先安裝llvm以及bcc編譯需要的cmake等工具，然後後過cmake編譯安裝。

安裝完成後，昨天提到的bcc自己寫好的kernel trace tools會被安裝到`/usr/share/bcc/tools`，因此可以直接cd到該目錄來玩，由於這些tools其實就是python script，所以其實也可以直接透過python3執行bcc repo下tools目錄內的python檔，其結果其實是一樣的。

同樣的還有examples這個資料夾下的範例也會被安裝到`/usr/share/bcc/examples`目錄下。

最後是透過docker的方式執行bcc。同樣參考bcc的[quickstart](https://github.com/iovisor/bcc/blob/master/QUICKSTART.md)文件，不過加上`--pid=host`

    docker run -it --rm \
      --pid=host \
      --privileged \
      -v /lib/modules:/lib/modules:ro \
      -v /usr/src:/usr/src:ro \
      -v /etc/localtime:/etc/localtime:ro \
      --workdir /usr/share/bcc/tools \
      zlim/bcc

但是不論是直接使用`zlim/bcc`還是透過bcc repo內的dockerfile自行編譯，目前測試起來還是有許多問題，使用zlim/bcc在執行部分的eBPF程式時會編譯失敗，直接透過dockerfile編譯初步測試也沒辦法build成功，因此目前自行編譯使用可能還是相對比較穩定簡單快速的方式。

由於在設置bcc開發環境時，踩到了許多坑，因此特別花一天的時間來聊安裝的部分，明天我們就可以正式來看bcc的程式碼了。

> 本系列30天鐵人文章同步發表在我的[個人部落格](https://blog.louisif.me/eBPF/Learn-eBPF-Serial-1-Abstract-and-Background/)
