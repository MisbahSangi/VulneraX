document.addEventListener("DOMContentLoaded", function() {
    console.log("VulneraX main.js v9 loaded");

    // Theme Toggle
    var themeToggle = document.getElementById("theme-toggle");
    var themeIcon = document.getElementById("theme-icon");
    var html = document.documentElement;

    function setTheme(theme) {
        html.setAttribute("data-theme", theme);
        localStorage.setItem("theme", theme);
        if (theme === "dark") {
            themeIcon.className = "bi bi-moon-fill";
        } else {
            themeIcon.className = "bi bi-sun-fill";
        }
    }

    var savedTheme = localStorage.getItem("theme") || "dark";
    setTheme(savedTheme);

    if (themeToggle) {
        themeToggle.addEventListener("click", function() {
            var current = html.getAttribute("data-theme");
            setTheme(current === "dark" ? "light" : "dark");
        });
    }

    // Remediation tips
    var remediationTips = {
        "XSS": "Sanitize all user inputs. Use Content-Security-Policy headers. Encode output data.",
        "SQL Injection": "Use parameterized queries. Never concatenate user input in SQL.",
        "Security Headers": "Add Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, HSTS headers.",
        "CSRF": "Implement CSRF tokens in all forms. Use SameSite cookie attribute.",
        "Directory Listing": "Disable directory listing in web server. Add index files.",
        "Weak TLS": "Enable HTTPS with TLS 1.2+. Add HSTS header.",
        "Insecure Transport": "Redirect all HTTP to HTTPS. Enable HSTS.",
        "Open Redirect": "Validate redirect URLs against whitelist.",
        "Sensitive Info Disclosure": "Remove sensitive data from responses. Disable debug mode.",
        "Clickjacking": "Add X-Frame-Options: DENY or CSP frame-ancestors.",
        "Cookie Security": "Set HttpOnly, Secure, and SameSite flags on cookies."
    };

    // DOM elements
    var form = document.getElementById("scan-form");
    var button = document.getElementById("scan-button");
    var btnText = document.getElementById("scan-button-text");
    var spinner = document.getElementById("scan-button-spinner");
    var cancelBtn = document.getElementById("cancel-scan-btn");
    var progressBar = document.getElementById("scan-progress-bar");
    var progressText = document.getElementById("scan-progress-text");
    var logPanel = document.getElementById("scan-log");
    var scanVisualization = document.getElementById("scan-visualization");
    var timeRemainingEl = document.getElementById("time-remaining");
    var notificationSound = document.getElementById("notification-sound");

    var statusInterval = null;
    var findingsChart = null;
    var stackedSeverityChart = null;
    var trendChart = null;
    var scanStartTime = null;
    var selectedFindings = new Set();
    var allFindings = [];
    var sortColumn = null;
    var sortDirection = "asc";
    var currentPage = 1;
    var pageSize = 10;

    var severityColors = {
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#3b82f6",
        info: "#22c55e"
    };

    var severityOrder = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        info: 1
    };

    function resetButtonUI() {
        if (button) button.disabled = false;
        if (btnText) btnText.textContent = "Start Scan";
        if (spinner) spinner.classList.add("d-none");
        if (cancelBtn) cancelBtn.classList.add("d-none");
        if (scanVisualization) scanVisualization.classList.add("d-none");
    }

    function showScanUI() {
        if (button) button.disabled = true;
        if (btnText) btnText.textContent = "Scanning...";
        if (spinner) spinner.classList.remove("d-none");
        if (cancelBtn) cancelBtn.classList.remove("d-none");
        if (scanVisualization) scanVisualization.classList.remove("d-none");
        scanStartTime = Date.now();
        resetCheckItems();
    }

    function resetCheckItems() {
        var items = document.querySelectorAll(".check-item");
        items.forEach(function(item) {
            item.classList.remove("active", "completed");
        });
    }

    function setCheckItemActive(phase) {
        var dominated = false;
        var items = document.querySelectorAll(".check-item");
        items.forEach(function(item) {
            var check = item.getAttribute("data-check");
            if (check === phase) {
                item.classList.add("active");
                item.classList.remove("completed");
                dominated = true;
            } else if (!dominated) {
                item.classList.remove("active");
                item.classList.add("completed");
            }
        });
        if (phase === "done") {
            items.forEach(function(item) {
                item.classList.remove("active");
                item.classList.add("completed");
            });
        }
    }

    function updateTimeRemaining(progress) {
        if (!scanStartTime || progress <= 0) {
            if (timeRemainingEl) timeRemainingEl.textContent = "Estimated time: calculating...";
            return;
        }
        var elapsed = (Date.now() - scanStartTime) / 1000;
        var total = elapsed / (progress / 100);
        var remaining = Math.max(0, total - elapsed);
        var mins = Math.floor(remaining / 60);
        var secs = Math.floor(remaining % 60);
        if (timeRemainingEl) {
            if (progress >= 100) {
                timeRemainingEl.textContent = "Scan complete!";
            } else {
                timeRemainingEl.textContent = "Time remaining: " + mins + "m " + secs + "s";
            }
        }
    }

    function playNotificationSound() {
        if (notificationSound) {
            notificationSound.currentTime = 0;
            notificationSound.play().catch(function() {});
        }
        if ("Notification" in window && Notification.permission === "granted") {
            new Notification("Scan Complete!", {
                body: "Your vulnerability scan has finished."
            });
        }
    }

    if ("Notification" in window && Notification.permission === "default") {
        Notification.requestPermission();
    }

    function updateSeverityCards(bySeverity) {
        var s = bySeverity || {};
        var el;
        el = document.getElementById("sev-critical");
        if (el) el.textContent = s.critical || 0;
        el = document.getElementById("sev-high");
        if (el) el.textContent = s.high || 0;
        el = document.getElementById("sev-medium");
        if (el) el.textContent = s.medium || 0;
        el = document.getElementById("sev-low");
        if (el) el.textContent = s.low || 0;
        el = document.getElementById("sev-info");
        if (el) el.textContent = s.info || 0;
    }

    function updateStats(history) {
        var total = history ? history.length : 0;
        var el = document.getElementById("stat-total-scans");
        if (el) el.textContent = total;

        var sum = 0;
        (history || []).forEach(function(item) {
            var m = (item.summary || "").match(/(\d+)/);
            if (m) sum += parseInt(m[1], 10);
        });
        el = document.getElementById("stat-avg-findings");
        if (el) el.textContent = total > 0 ? (sum / total).toFixed(1) : "0";

        if (history && history.length > 0) {
            var last = history[history.length - 1];
            el = document.getElementById("stat-last-scan");
            if (el) el.textContent = (last.timestamp || "").substring(5, 16);
        }
    }

    function updateSelectedCount() {
        var count = selectedFindings.size;
        var el = document.getElementById("selected-count");
        if (el) el.textContent = count;
        var btn = document.getElementById("export-selected-btn");
        if (btn) btn.disabled = count === 0;
    }

    function getRemediation(type) {
        return remediationTips[type] || "Review the finding and apply appropriate security measures.";
    }

    async function refreshResultsFromServer() {
        try {
            var res = await fetch("/last-results");
            if (!res.ok) return;
            var data = await res.json();

            allFindings = data.findings || [];
            var summary = data.summary || {};
            var byType = summary.by_type || {};
            var bySeverity = summary.by_severity || {};
            var byTypeAndSeverity = summary.by_type_and_severity || {};
            var history = data.history || [];
            var targetUrl = data.target_url || "";

            var el;
            el = document.getElementById("results-target");
            if (el) el.textContent = targetUrl;
            el = document.getElementById("results-meta");
            if (el) el.textContent = "Total findings: " + (summary.total || 0);
            el = document.getElementById("findings-badge");
            if (el) el.textContent = allFindings.length + " finding" + (allFindings.length === 1 ? "" : "s");

            updateSeverityCards(bySeverity);
            updateStats(history);
            updateTypeFilter(byType);
            renderFindingsTable();
            updateChart(byType);
            updateStackedSeverityChart(byTypeAndSeverity);
            updateTrendChart(history);
            updateRecentScans(history);

            selectedFindings.clear();
            updateSelectedCount();
        } catch (e) {
            console.error("Error refreshing results", e);
        }
    }

    function updateTypeFilter(byType) {
        var select = document.getElementById("type_filter");
        if (!select) return;
        var current = select.value;
        select.innerHTML = '<option value="all">All types</option>';
        Object.keys(byType).forEach(function(t) {
            var opt = document.createElement("option");
            opt.value = t;
            opt.textContent = t + " (" + byType[t] + ")";
            select.appendChild(opt);
        });
        select.value = current;
    }

    function getFilteredFindings() {
        var sevFilter = document.getElementById("severity_filter");
        var typeFilter = document.getElementById("type_filter");
        var searchBox = document.getElementById("search_box");

        var sevVal = sevFilter ? sevFilter.value : "all";
        var typeVal = typeFilter ? typeFilter.value : "all";
        var searchVal = searchBox ? searchBox.value.toLowerCase() : "";

        return allFindings.filter(function(f) {
            var sev = (f.severity || "").toLowerCase();
            var type = f.type || "";
            var url = (f.url || "").toLowerCase();
            var evidence = (f.evidence || "").toLowerCase();

            var passSev = sevVal === "all" ||
                (sevVal === "high_critical" && (sev === "high" || sev === "critical")) ||
                (sevVal === "medium_plus" && severityOrder[sev] >= 3);
            var passType = typeVal === "all" || type === typeVal;
            var passSearch = !searchVal || url.indexOf(searchVal) !== -1 || evidence.indexOf(searchVal) !== -1;

            return passSev && passType && passSearch;
        });
    }

    function renderFindingsTable() {
        var tbody = document.getElementById("findings-tbody");
        if (!tbody) return;

        var filtered = getFilteredFindings();

        if (sortColumn) {
            filtered.sort(function(a, b) {
                var aVal, bVal;
                if (sortColumn === "severity") {
                    aVal = severityOrder[(a.severity || "").toLowerCase()] || 0;
                    bVal = severityOrder[(b.severity || "").toLowerCase()] || 0;
                } else {
                    aVal = (a[sortColumn] || "").toLowerCase();
                    bVal = (b[sortColumn] || "").toLowerCase();
                }
                if (aVal < bVal) return sortDirection === "asc" ? -1 : 1;
                if (aVal > bVal) return sortDirection === "asc" ? 1 : -1;
                return 0;
            });
        }

        var totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
        if (currentPage > totalPages) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;

        var start = (currentPage - 1) * pageSize;
        var pageItems = filtered.slice(start, start + pageSize);

        tbody.innerHTML = "";

        pageItems.forEach(function(f, idx) {
            var realIdx = start + idx;
            var typeVal = f.type || "";
            var urlVal = f.url || "";
            var sev = (f.severity || "").toLowerCase();
            var evidVal = f.evidence || "";
            var remediation = getRemediation(typeVal);
            var uniqueId = "finding-" + realIdx;
            var checked = selectedFindings.has(realIdx) ? "checked" : "";

            var tr = document.createElement("tr");
            tr.setAttribute("data-index", realIdx);

            tr.innerHTML = '<td><input type="checkbox" class="select-checkbox row-select" data-index="' + realIdx + '" ' + checked + '></td>' +
                '<td class="fw-semibold">' + typeVal + '</td>' +
                '<td style="max-width: 180px"><small class="text-truncate d-block" style="max-width:160px" title="' + urlVal + '">' + urlVal + '</small></td>' +
                '<td><span class="severity-badge ' + sev + '">' + sev + '</span></td>' +
                '<td class="evidence-cell" data-id="' + uniqueId + '">' +
                '<small class="evidence-short">' + evidVal.substring(0, 50) + (evidVal.length > 50 ? '... <i class="bi bi-chevron-down"></i>' : '') + '</small>' +
                '<div class="evidence-full" id="' + uniqueId + '">' +
                '<strong>Evidence: </strong><br>' + evidVal +
                '<div class="remediation-tip"><strong>Remediation:</strong> ' + remediation + '</div>' +
                '</div></td>';

            tbody.appendChild(tr);
        });

        var pageInfo = document.getElementById("page-info");
        if (pageInfo) pageInfo.textContent = "Page " + currentPage + "/" + totalPages + " (" + filtered.length + ")";

        var prevBtn = document.getElementById("prev-page-btn");
        var nextBtn = document.getElementById("next-page-btn");
        if (prevBtn) prevBtn.disabled = currentPage <= 1;
        if (nextBtn) nextBtn.disabled = currentPage >= totalPages;

        attachTableEventListeners();
    }

    function attachTableEventListeners() {
        document.querySelectorAll(".evidence-cell").forEach(function(cell) {
            cell.onclick = function(e) {
                if (e.target.type === "checkbox") return;
                var id = cell.getAttribute("data-id");
                var fullDiv = document.getElementById(id);
                if (fullDiv) {
                    fullDiv.classList.toggle("show");
                    var icon = cell.querySelector(".bi-chevron-down, .bi-chevron-up");
                    if (icon) icon.className = fullDiv.classList.contains("show") ? "bi bi-chevron-up" : "bi bi-chevron-down";
                }
            };
        });

        document.querySelectorAll(".row-select").forEach(function(cb) {
            cb.onchange = function(e) {
                e.stopPropagation();
                var idx = parseInt(cb.getAttribute("data-index"), 10);
                if (cb.checked) {
                    selectedFindings.add(idx);
                } else {
                    selectedFindings.delete(idx);
                }
                updateSelectedCount();
            };
        });
    }

    var selectAll = document.getElementById("select-all");
    if (selectAll) {
        selectAll.onchange = function() {
            document.querySelectorAll(".row-select").forEach(function(cb) {
                cb.checked = selectAll.checked;
                var idx = parseInt(cb.getAttribute("data-index"), 10);
                if (selectAll.checked) {
                    selectedFindings.add(idx);
                } else {
                    selectedFindings.delete(idx);
                }
            });
            updateSelectedCount();
        };
    }

    document.querySelectorAll("th[data-sort]").forEach(function(th) {
        th.onclick = function() {
            var col = th.getAttribute("data-sort");
            if (sortColumn === col) {
                sortDirection = sortDirection === "asc" ? "desc" : "asc";
            } else {
                sortColumn = col;
                sortDirection = "asc";
            }
            document.querySelectorAll("th[data-sort]").forEach(function(h) {
                h.classList.remove("sorted");
            });
            th.classList.add("sorted");
            renderFindingsTable();
        };
    });

    var sevFilterEl = document.getElementById("severity_filter");
    var typeFilterEl = document.getElementById("type_filter");
    var searchBoxEl = document.getElementById("search_box");
    var prevBtnEl = document.getElementById("prev-page-btn");
    var nextBtnEl = document.getElementById("next-page-btn");

    if (sevFilterEl) sevFilterEl.onchange = function() {
        currentPage = 1;
        renderFindingsTable();
    };
    if (typeFilterEl) typeFilterEl.onchange = function() {
        currentPage = 1;
        renderFindingsTable();
    };
    if (searchBoxEl) searchBoxEl.oninput = function() {
        currentPage = 1;
        renderFindingsTable();
    };
    if (prevBtnEl) prevBtnEl.onclick = function(e) {
        e.preventDefault();
        currentPage--;
        renderFindingsTable();
    };
    if (nextBtnEl) nextBtnEl.onclick = function(e) {
        e.preventDefault();
        currentPage++;
        renderFindingsTable();
    };

    var exportBtn = document.getElementById("export-selected-btn");
    if (exportBtn) {
        exportBtn.onclick = function() {
            if (selectedFindings.size === 0) return;
            var selected = [];
            selectedFindings.forEach(function(idx) {
                if (allFindings[idx]) selected.push(allFindings[idx]);
            });
            var blob = new Blob([JSON.stringify(selected, null, 2)], {
                type: "application/json"
            });
            var url = URL.createObjectURL(blob);
            var a = document.createElement("a");
            a.href = url;
            a.download = "selected_findings.json";
            a.click();
            URL.revokeObjectURL(url);
        };
    }

    function updateChart(byType) {
        var canvas = document.getElementById("findingsChart");
        if (!canvas || !window.Chart) return;

        var labels = Object.keys(byType || {});
        var data = labels.map(function(k) {
            return byType[k];
        });
        var ctx = canvas.getContext("2d");

        if (findingsChart) {
            findingsChart.data.labels = labels;
            findingsChart.data.datasets[0].data = data;
            findingsChart.update();
        } else if (labels.length > 0) {
            findingsChart = new Chart(ctx, {
                type: "doughnut",
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: ["#3b82f6", "#f97316", "#eab308", "#22c55e", "#ef4444", "#8b5cf6", "#ec4899"],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                boxWidth: 8,
                                padding: 4,
                                font: {
                                    size: 9
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    function updateStackedSeverityChart(byTypeAndSeverity) {
        var canvas = document.getElementById("stackedSeverityChart");
        if (!canvas || !window.Chart) return;

        var types = Object.keys(byTypeAndSeverity || {});
        if (types.length === 0) {
            if (stackedSeverityChart) {
                stackedSeverityChart.destroy();
                stackedSeverityChart = null;
            }
            return;
        }

        var sevList = ["critical", "high", "medium", "low", "info"];
        var datasets = sevList.map(function(sev) {
            return {
                label: sev.charAt(0).toUpperCase() + sev.slice(1),
                data: types.map(function(t) {
                    return (byTypeAndSeverity[t] || {})[sev] || 0;
                }),
                backgroundColor: severityColors[sev],
                barThickness: 14
            };
        });

        var ctx = canvas.getContext("2d");

        if (stackedSeverityChart) {
            stackedSeverityChart.data.labels = types;
            stackedSeverityChart.data.datasets = datasets;
            stackedSeverityChart.update();
        } else {
            stackedSeverityChart = new Chart(ctx, {
                type: "bar",
                data: {
                    labels: types,
                    datasets: datasets
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: "y",
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        x: {
                            stacked: true,
                            ticks: {
                                font: {
                                    size: 8
                                }
                            },
                            grid: {
                                display: false
                            }
                        },
                        y: {
                            stacked: true,
                            ticks: {
                                font: {
                                    size: 8
                                }
                            },
                            grid: {
                                display: false
                            }
                        }
                    }
                }
            });
        }
    }

    function updateTrendChart(history) {
        var canvas = document.getElementById("trendChart");
        if (!canvas || !window.Chart) return;

        if (!history || history.length === 0) {
            if (trendChart) {
                trendChart.destroy();
                trendChart = null;
            }
            return;
        }

        var labels = [];
        var data = [];

        history.slice(-10).forEach(function(item) {
            labels.push((item.timestamp || "").substring(5, 10));
            var m = (item.summary || "").match(/(\d+)/);
            data.push(m ? parseInt(m[1], 10) : 0);
        });

        var ctx = canvas.getContext("2d");

        if (trendChart) {
            trendChart.data.labels = labels;
            trendChart.data.datasets[0].data = data;
            trendChart.update();
        } else {
            trendChart = new Chart(ctx, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        borderColor: "#3b82f6",
                        backgroundColor: "rgba(59,130,246,0.1)",
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1,
                                font: {
                                    size: 8
                                }
                            },
                            grid: {
                                color: "rgba(150,150,150,0.1)"
                            }
                        },
                        x: {
                            ticks: {
                                font: {
                                    size: 8
                                }
                            },
                            grid: {
                                display: false
                            }
                        }
                    }
                }
            });
        }
    }

    function updateRecentScans(history) {
        var list = document.getElementById("recent-scans-list");
        if (!list) return;

        list.innerHTML = "";
        (history || []).slice(-10).reverse().forEach(function(item) {
            var li = document.createElement("li");
            li.className = "list-group-item d-flex justify-content-between align-items-center";
            li.innerHTML = '<div><strong>' + item.target + '</strong><br><small class="text-muted">' + item.timestamp + '</small></div><span class="badge bg-secondary">' + item.summary + '</span>';
            list.appendChild(li);
        });
    }

    async function fetchAndRenderStatus(stopWhenDone) {
        try {
            var res = await fetch("/scan-status");
            if (!res.ok) return;
            var data = await res.json();

            var pct = data.progress || 0;
            var phase = data.phase || "idle";
            var lines = data.log_lines || [];
            var status = data.status || "idle";

            if (progressBar && progressText) {
                progressBar.style.width = pct + "%";
                progressText.textContent = phase + " (" + pct + "%)";
            }

            if (logPanel) {
                logPanel.textContent = lines.join("\n");
                logPanel.scrollTop = logPanel.scrollHeight;
            }

            setCheckItemActive(phase);
            updateTimeRemaining(pct);

            if (status === "done" || status === "idle") {
                if (stopWhenDone && statusInterval) {
                    clearInterval(statusInterval);
                    statusInterval = null;
                }
                resetButtonUI();
                if (status === "done") {
                    playNotificationSound();
                    refreshResultsFromServer();
                }
            }
        } catch (e) {
            console.error("Status error", e);
        }
    }

    function startStatusPolling() {
        if (statusInterval) clearInterval(statusInterval);
        fetchAndRenderStatus(true);
        statusInterval = setInterval(function() {
            fetchAndRenderStatus(true);
        }, 800);
    }

    if (cancelBtn) {
        cancelBtn.onclick = async function() {
            try {
                await fetch("/cancel-scan", {
                    method: "POST"
                });
                resetButtonUI();
                if (statusInterval) {
                    clearInterval(statusInterval);
                    statusInterval = null;
                }
            } catch (e) {
                console.error("Cancel error", e);
            }
        };
    }

    if (form && button) {
        form.onsubmit = async function(event) {
            event.preventDefault();
            var formData = new FormData(form);

            showScanUI();
            if (logPanel) logPanel.textContent = "";

            try {
                var res = await fetch("/scan", {
                    method: "POST",
                    body: formData
                });
                if (!res.ok) {
                    console.error("Scan request failed");
                    resetButtonUI();
                    return;
                }
                var data = await res.json();
                if (!data.ok) {
                    console.error("Scan error:", data.error);
                    alert("Error: " + data.error);
                    resetButtonUI();
                    return;
                }
                startStatusPolling();
            } catch (e) {
                console.error("Scan error", e);
                resetButtonUI();
            }
        };
    }

    fetchAndRenderStatus(false);
    refreshResultsFromServer();

    window.__vx_refresh = refreshResultsFromServer;
});