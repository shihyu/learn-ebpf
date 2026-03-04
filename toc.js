// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><a href="index.html"><strong aria-hidden="true">1.</strong> 教練我想玩eBPF</a></li><li class="chapter-item expanded "><a href="complete.html"><strong aria-hidden="true">2.</strong> 完整合輯</a></li><li class="chapter-item expanded "><a href="day-01.html"><strong aria-hidden="true">3.</strong> Day 01 - 前言</a></li><li class="chapter-item expanded "><a href="day-02.html"><strong aria-hidden="true">4.</strong> Day 02 - eBPF的前世</a></li><li class="chapter-item expanded "><a href="day-03.html"><strong aria-hidden="true">5.</strong> Day 03 - eBPF的應用</a></li><li class="chapter-item expanded "><a href="day-04.html"><strong aria-hidden="true">6.</strong> Day 04 - eBPF基本知識(1) - Program type</a></li><li class="chapter-item expanded "><a href="day-05.html"><strong aria-hidden="true">7.</strong> Day 05 - eBPF基本知識(2) - 如何撰寫</a></li><li class="chapter-item expanded "><a href="day-06.html"><strong aria-hidden="true">8.</strong> Day 06 - eBPF基本知識(3) - 使用條件與載入流程</a></li><li class="chapter-item expanded "><a href="day-07.html"><strong aria-hidden="true">9.</strong> Day 07 - eBPF基本知識(4) - JIT</a></li><li class="chapter-item expanded "><a href="day-08.html"><strong aria-hidden="true">10.</strong> Day 08 - eBPF基本知識(5) - 生命週期</a></li><li class="chapter-item expanded "><a href="day-09.html"><strong aria-hidden="true">11.</strong> Day 09 - eBPF基本知識(6) - Helper Funtions</a></li><li class="chapter-item expanded "><a href="day-10.html"><strong aria-hidden="true">12.</strong> Day 10 - eBPF基本知識(7) - debug tracing</a></li><li class="chapter-item expanded "><a href="day-11.html"><strong aria-hidden="true">13.</strong> Day 11 - eBPF基本知識(8) - map (上)</a></li><li class="chapter-item expanded "><a href="day-12.html"><strong aria-hidden="true">14.</strong> Day 12 - eBPF基本知識(9) - map(下)</a></li><li class="chapter-item expanded "><a href="day-13.html"><strong aria-hidden="true">15.</strong> Day 13 - eBPF基本知識(10) - Tail call</a></li><li class="chapter-item expanded "><a href="day-14.html"><strong aria-hidden="true">16.</strong> Day 14 - BCC 簡介</a></li><li class="chapter-item expanded "><a href="day-15.html"><strong aria-hidden="true">17.</strong> Day 15 - BCC 安裝</a></li><li class="chapter-item expanded "><a href="day-16.html"><strong aria-hidden="true">18.</strong> Day 16 - BCC tcpconnect (上)</a></li><li class="chapter-item expanded "><a href="day-17.html"><strong aria-hidden="true">19.</strong> Day 17 - BCC tcpconnect (下)</a></li><li class="chapter-item expanded "><a href="day-18.html"><strong aria-hidden="true">20.</strong> Day 18 - BCC HTTP filter</a></li><li class="chapter-item expanded "><a href="day-19.html"><strong aria-hidden="true">21.</strong> Day 19 - 外傳 - Socket filter 底層摸索 (上)</a></li><li class="chapter-item expanded "><a href="day-20.html"><strong aria-hidden="true">22.</strong> Day 20 - 外傳 - Socket filter 底層探索 (下)</a></li><li class="chapter-item expanded "><a href="day-21.html"><strong aria-hidden="true">23.</strong> Day 21 - XDP概念</a></li><li class="chapter-item expanded "><a href="day-22.html"><strong aria-hidden="true">24.</strong> Day 22 - BCC xdp_redirect_map</a></li><li class="chapter-item expanded "><a href="day-23.html"><strong aria-hidden="true">25.</strong> Day 23 - TC概念</a></li><li class="chapter-item expanded "><a href="day-24.html"><strong aria-hidden="true">26.</strong> Day 24 - BCC neighbor_sharing</a></li><li class="chapter-item expanded "><a href="day-25.html"><strong aria-hidden="true">27.</strong> Day 25 - eBPC tc direct</a></li><li class="chapter-item expanded "><a href="day-26.html"><strong aria-hidden="true">28.</strong> Day 26 - Cgroups</a></li><li class="chapter-item expanded "><a href="day-27.html"><strong aria-hidden="true">29.</strong> Day 27 - BCC sockmap (上)</a></li><li class="chapter-item expanded "><a href="day-28.html"><strong aria-hidden="true">30.</strong> Day 28 - BCC sockmap (下)</a></li><li class="chapter-item expanded "><a href="day-29.html"><strong aria-hidden="true">31.</strong> Day 29 - eBPF helper function速覽 (上)</a></li><li class="chapter-item expanded "><a href="day-30.html"><strong aria-hidden="true">32.</strong> Day 30 - eBPF helper function速覽 (下)</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
