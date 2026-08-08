

        let currentScans = {};

        /* KEEP UI SAME */
        function showSection(section) {
            document.getElementById("scan").style.display = "none";
            document.getElementById("alerts").style.display = "none";
            document.getElementById("history").style.display = "none";
            document.getElementById("surfaceView").style.display = "none";
            document.getElementById(section).style.display = "block";
        }

        /* USERS */
        function loadUsers() {
            document.getElementById("usersModal").style.display = "block";
            fetch("/users")
                .then(res => res.json())
                .then(data => {
                    let html = "";
                    data.forEach(u => {
                        html += `
                            <div class="user-item">
                                <span style="flex-grow: 1;">👤 ${u.username} ${u.is_admin ? '<span style="color:#38bdf8; font-size:0.7rem; margin-left:5px;">(Admin)</span>' : ''}</span>
                                ${u.can_delete ? `<button class="delete-user-btn" onclick="deleteUser(${u.id})">Remove</button>` : ''}
                            </div>`;
                    });
                    document.getElementById("usersList").innerHTML = html || "No users";
                });
        }

        function deleteUser(userId) {
            if (!confirm("Are you sure you want to remove this user?")) return;

            fetch(`/admin/delete_user/${userId}`, { method: 'DELETE' })
                .then(res => res.json())
                .then(data => {
                    loadUsers();
                })
                .catch(err => alert("Error deleting user"));
        }

        function openCreateUser() {
            document.getElementById("createUserModal").style.display = "block";
        }

        function closeCreateUser() {
            document.getElementById("createUserModal").style.display = "none";
        }

        function confirmCreateUser() {
            let u = document.getElementById("new_username").value.trim();
            let p = document.getElementById("new_password").value;
            let a = document.getElementById("new_is_admin").checked;

            if (!u || !p) return alert("Username and Password required");

            let data = new URLSearchParams();
            data.append("username", u);
            data.append("password", p);
            if (a) data.append("is_admin", "on");

            axios.post("/admin/add_user", data)
                .then(res => {
                    alert("User created successfully!");
                    closeCreateUser();
                    loadUsers();
                })
                .catch(err => alert(err.response.data.error || "Failed to create user"));
        }

        function closeUsers() {
            document.getElementById("usersModal").style.display = "none";
        }

        /* SCHEDULE SCANS */
        function openSchedule() {
            document.getElementById("sched_target").value = document.getElementById("target").value;
            document.getElementById("scheduleModal").style.display = "block";
        }

        function closeSchedule() {
            document.getElementById("scheduleModal").style.display = "none";
        }

        function confirmSchedule() {
            let target = document.getElementById("sched_target").value;
            let freq = document.getElementById("sched_freq").value;
            let hour = document.getElementById("sched_hour").value;

            if (!target) return alert("Enter a target URL");

            let data = new URLSearchParams();
            data.append("target", target);
            data.append("frequency", freq);
            data.append("hour", hour);

            axios.post("/schedule_scan", data)
                .then(res => {
                    alert(res.data.message);
                    closeSchedule();
                    loadHistory(); // refresh history to show scheduled job
                })
                .catch(err => {
                    console.error(err);
                    alert("Failed to schedule scan");
                });
        }

        /* THEME TOGGLE */
        /* THEME & SECTION LOGIC */
        function showSection(name) {
            const sections = ['scan', 'alerts', 'history', 'assets', 'vulns'];
            sections.forEach(s => {
                const el = document.getElementById(s);
                if (el) el.style.display = (s === name) ? 'block' : 'none';
            });

            if (name === 'scan') {
                document.getElementById('scanList').style.display = 'block';
            } else {
                document.getElementById('scanList').style.display = 'none';
            }

            if (name === 'assets') loadAssets();
            if (name === 'vulns') loadVulnerabilities();
        }

        /* VULN TRACKER */
        function loadVulnerabilities(filterStatus = null) {
            fetch("/api/vulnerabilities")
                .then(res => res.json())
                .then(data => {
                    const resolvedNum = data.filter(v => v.status === 'Resolved').length;
                    const resEl = document.getElementById("resolvedCount");
                    if (resEl) resEl.innerText = resolvedNum;

                    let html = "";
                    data.forEach(v => {
                        if (filterStatus && v.status !== filterStatus) return;

                        let compTags = "";
                        try {
                            const tags = JSON.parse(v.compliance_tags || '[]');
                            compTags = tags.map(t => `<span style="font-size:0.6rem; border:1px solid var(--accent-secondary); padding:1px 4px; border-radius:4px; margin-right:4px;">${t}</span>`).join('');
                        } catch (e) { }

                        html += `
                            <tr>
                                <td>
                                    <strong>${v.alert}</strong>
                                    <div style="margin-top:4px;">${compTags}</div>
                                </td>
                                <td>${v.asset_name || 'Individual IP'}</td>
                                <td><span class="risk-badge risk-${v.risk.toLowerCase()}">${v.risk_score}</span></td>
                                <td><span class="risk-badge" style="background:rgba(255,255,255,0.05);">${v.status}</span></td>
                                <td>${v.date_found.split('T')[0]}</td>
                                <td>
                                    <button onclick='showDrillDown(${JSON.stringify(v).replace(/'/g, "&apos;")})' style="background:none; border:none; color:#38bdf8; cursor:pointer;"><i class="fas fa-edit"></i></button>
                                </td>
                            </tr>
                        `;
                    });
                    document.getElementById("vulnTrackerBody").innerHTML = html || '<tr><td colspan="6" style="text-align:center;">No vulnerabilities indexed.</td></tr>';
                });
        }

        /* ASSETS */
        function loadAssets() {
            fetch("/api/assets")
                .then(res => res.json())
                .then(data => {
                    let html = "";
                    data.forEach(a => {
                        html += `
                            <tr>
                                <td><strong>${a.name}</strong></td>
                                <td>${a.target}</td>
                                <td><span class="risk-badge risk-info">${a.environment}</span></td>
                                <td><span class="risk-badge risk-${a.criticality.toLowerCase()}">${a.criticality}</span></td>
                                <td>${a.internet_facing ? '🌐 External' : '🔒 Internal'}</td>
                                <td>
                                    <button onclick="startAssetScan('${a.target}')" style="background:none; border:none; color:#38bdf8; cursor:pointer;" title="Quick Scan"><i class="fas fa-play"></i></button>
                                    <button onclick="deleteAsset(${a.id})" style="background:none; border:none; color:#ef4444; cursor:pointer; margin-left:10px;"><i class="fas fa-trash"></i></button>
                                </td>
                            </tr>
                        `;
                    });
                    document.getElementById("assetBody").innerHTML = html || '<tr><td colspan="6" style="text-align:center;">No assets recorded yet.</td></tr>';
                });
        }

        function openAddAsset() {
            document.getElementById("addAssetModal").style.display = "block";
        }

        function closeAddAsset() {
            document.getElementById("addAssetModal").style.display = "none";
        }

        function confirmAddAsset() {
            const data = {
                name: document.getElementById("asset_name").value,
                target: document.getElementById("asset_target").value,
                env: document.getElementById("asset_env").value,
                criticality: document.getElementById("asset_criticality").value,
                internet: document.getElementById("asset_internet").checked
            };

            if (!data.name || !data.target) return alert("Name and Target required");

            axios.post("/api/admin/add_asset", data)
                .then(res => {
                    closeAddAsset();
                    loadAssets();
                })
                .catch(err => alert("Failed to add asset"));
        }

        function deleteAsset(id) {
            if (!confirm("Remove asset?")) return;
            axios.delete(`/api/admin/delete_asset/${id}`)
                .then(() => loadAssets());
        }

        function startAssetScan(target) {
            showSection('scan');
            document.getElementById("target").value = target;
            startScan();
        }

        function changeTheme() {
            const theme = document.getElementById("themeSelect").value;
            document.documentElement.setAttribute("data-theme-name", theme);
            localStorage.setItem("theme-name", theme);
        }

        function setTheme(mode) {
            const body = document.documentElement;
            body.setAttribute("data-theme", mode);
            const icon = document.getElementById("themeIcon");
            if (mode === 'light') {
                icon.className = "fas fa-sun";
            } else {
                icon.className = "fas fa-moon";
            }
            localStorage.setItem("theme", mode);
        }

        function toggleTheme() {
            const body = document.documentElement;
            const current = body.getAttribute("data-theme") || "light";
            setTheme(current === "light" ? "dark" : "light");
        }

        // Apply saved theme & language
        document.addEventListener("DOMContentLoaded", () => {
            const savedTheme = localStorage.getItem("theme") || "light";
            setTheme(savedTheme);

            const savedThemeName = localStorage.getItem("theme-name") || "default";
            const themeSel = document.getElementById("themeSelect");
            if(themeSel) themeSel.value = savedThemeName;
            document.documentElement.setAttribute("data-theme-name", savedThemeName);

            const savedLang = localStorage.getItem("language") || "en";
            applyLang(savedLang);

            // Initial Data Load
            loadTrends();
            loadHistory();
            loadAssets();
            loadVulnerabilities();
            loadNotifications();
            loadSavedScans();
            
            showSection('scan');

            setInterval(loadNotifications, 30000); 
        });

        /* NOTIFICATIONS */
        function loadNotifications() {
            fetch("/api/notifications")
                .then(res => res.json())
                .then(data => {
                    const badge = document.getElementById("notifBadge");
                    const list = document.getElementById("notifList");
                    const unread = data.filter(n => !n.is_read).length;

                    if (unread > 0) {
                        badge.innerText = unread;
                        badge.style.display = "block";
                    } else {
                        badge.style.display = "none";
                    }

                    if (data.length === 0) {
                        list.innerHTML = `<p style="font-size:0.8rem; color:var(--text-secondary);">No notifications</p>`;
                    } else {
                        list.innerHTML = data.map(n => `
                            <div style="padding:0.75rem; border-bottom:1px solid rgba(255,255,255,0.05); cursor:pointer; opacity: ${n.is_read ? 0.6 : 1}" onclick="markRead(${n.id})">
                                <div style="font-size:0.7rem; color:var(--accent-primary); text-transform:uppercase; font-weight:bold;">${n.type}</div>
                                <div style="font-size:0.85rem; margin-top:0.25rem;">${n.message}</div>
                                <div style="font-size:0.6rem; color:var(--text-secondary); margin-top:0.25rem;">${n.date}</div>
                            </div>
                        `).join('') + `<button onclick="clearNotifs()" style="width:100%; padding:0.5rem; background:none; border:none; color:var(--text-secondary); font-size:0.7rem; cursor:pointer;">Mark all as read</button>`;
                    }
                });
        }

        function markRead(id) {
            axios.post(`/api/notifications/read/${id}`).then(loadNotifications);
        }

        function clearNotifs() {
            axios.post('/api/notifications/clear').then(loadNotifications);
        }

        /* VULN STATUS */
        let currentEditingVuln = null;
        function showDrillDown(v) {
            currentEditingVuln = v;
            document.getElementById("drillDownModal").style.display = "block";
            document.getElementById("drillDownTitle").innerText = v.alert;
            document.getElementById("vulnStatus").value = v.status || "Open";

            document.getElementById("drillDownContent").innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="risk-badge risk-${v.risk.toLowerCase()}">${v.risk}</span>
                    <span style="font-size:0.8rem; color:var(--text-secondary);">Risk Score: <strong>${v.risk_score || 'N/A'}</strong></span>
                </div>
                <p style="margin-top:1rem;">${v.description}</p>
                <h4>Solution</h4>
                <p>${v.solution}</p>
                ${v.url ? `<h4>Location</h4><p style="word-break:break-all; font-family:monospace; background:rgba(0,0,0,0.2); padding:0.5rem; border-radius:0.25rem;">${v.url}</p>` : ''}
            `;
        }

        function updateVulnStatus() {
            const status = document.getElementById("vulnStatus").value;
            if (!currentEditingVuln || !currentEditingVuln.id) return alert("Select a vulnerability first");

            axios.post("/api/vulnerability/status", {
                id: currentEditingVuln.id,
                status: status
            })
                .then(res => {
                    alert("Status updated successfully!");
                    closeDrillDown();
                    loadVulnerabilities();
                })
                .catch(err => {
                    alert(err.response?.data?.error || "Failed to update status");
                });
        }

        /* TRENDS */
        let trendChart = null;
        function loadTrends() {
            fetch("/api/trends")
                .then(res => res.json())
                .then(data => {
                    const ctx = document.getElementById('trendChart').getContext('2d');
                    if (trendChart) trendChart.destroy();

                    trendChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: data.map(d => d.date),
                            datasets: [
                                { label: 'High', data: data.map(d => d.high), borderColor: '#ef4444', tension: 0.4 },
                                { label: 'Medium', data: data.map(d => d.medium), borderColor: '#f59e0b', tension: 0.4 }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: { legend: { display: false } },
                            scales: {
                                x: { display: false },
                                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } }
                            }
                        }
                    });
                });
        }

        /* SCAN START */
        function startScan() {
            let targetInput = document.getElementById("target");
            let target = targetInput.value;
            let profile = document.getElementById("scanProfile").value;

            if (!target) return alert("Enter target");

            const payload = {
                target: target,
                profile: profile,
                use_nmap: document.getElementById("nmapCheck").checked,
                use_zap: document.getElementById("zapCheck").checked
            };

            axios.post("/api/trigger", payload)
                .then(res => {
                    let id = res.data.scan_id;
                    currentScans[id] = { target: target };
                    targetInput.value = "";

                    createScanCard(id, target);
                    pollScan(id);
                })
                .catch(err => {
                    console.error("Scan Error:", err);
                    const msg = err.response && err.response.data && err.response.data.error ? err.response.data.error : "Failed to initiate scan.";
                    alert("Error: " + msg);
                });
        }

        /* SCAN CARD */
        function createScanCard(id, target) {
            let div = document.createElement("div");
            div.className = "scan-card";
            div.id = id;

            div.innerHTML = `
        <h4>🌐 ${target}</h4>
        <p>Status: <span id="status_${id}">Starting...</span></p>

        Spider
        <div class="progress-container">
            <div class="progress-bar" id="spider_${id}">0%</div>
        </div>

        Active
        <div class="progress-container">
            <div class="progress-bar" id="active_${id}">0%</div>
        </div>

        Nmap
        <div class="progress-container">
            <div class="progress-bar" id="nmap_${id}">0%</div>
        </div>

        <!-- REPORT DROPDOWN -->
        <div class="dropdown" style="margin-top:10px;">
            <button>📥 Download Report <i class="fas fa-chevron-down" style="font-size: 0.7rem; margin-left: 0.5rem; opacity: 0.7;"></i></button>
            <div class="dropdown-content">
                <button onclick="downloadSingle('${id}','pdf')">PDF</button>
                <button onclick="downloadSingle('${id}','html')">HTML</button>
                <button onclick="downloadSingle('${id}','excel')">Excel</button>
            </div>
        </div>

        <button class="terminate-btn" onclick="terminateScan('${id}')">Terminate</button>
    `;

            document.getElementById("scanList").prepend(div);
        }

        /* POLLING */
        function pollScan(id) {
            let interval = setInterval(() => {
                fetch(`/status/${id}`)
                    .then(res => res.json())
                    .then(data => {
                        document.getElementById(`status_${id}`).innerText = data.status;
                        updateBar(`spider_${id}`, data.spider || 0);
                        updateBar(`active_${id}`, data.active || 0);
                        updateBar(`nmap_${id}`, data.nmap || 0);

                        if (data.status === "Completed" || data.status === "Terminated" || data.status.includes("Failed") || data.status === "Not Found") {
                            clearInterval(interval);

                            let card = document.getElementById(id);
                            if (card) {
                                let termBtn = card.querySelector(".terminate-btn");
                                if (termBtn) termBtn.remove();

                                // Also show a "View Results" link?
                                let resLink = document.createElement("button");
                                resLink.innerText = "📁 View Results";
                                resLink.className = "history-link";
                                resLink.style.marginTop = "10px";
                                resLink.onclick = () => viewDetails(id);
                                card.appendChild(resLink);
                            }
                            loadHistory();
                        }
                    });
            }, 1000);
        }

        function updateBar(id, val) {
            let el = document.getElementById(id);
            if (el) {
                el.style.width = val + "%";
                el.innerText = val + "%";
            }
        }

        /* STATS LOGIC */
        function updateStats(data) {
            let totalFixed = 0;
            data.forEach(s => totalFixed += (s.fixed ? s.fixed.length : 0));
            // Keep the previous logic or combine with tracker
            // document.getElementById("resolvedCount").innerText = totalFixed;
        }

        function loadHistory() {
            showSection('history');
            fetch("/api/history")
                .then(res => res.json())
                .then(data => {
                    let html = "";
                    data.forEach(h => {
                        let statusColor = h.is_scheduled ? "var(--accent-secondary)" : (h.status === "Completed" ? "var(--success)" : "var(--danger)");
                        html += `
                            <tr>
                                <td><div style="max-width:200px; overflow:hidden; text-overflow:ellipsis;">${h.target}</div></td>
                                <td><div style="font-size:0.75rem; color:${statusColor}">${h.is_scheduled ? '📅 Next: ' + h.next_run_time : h.date.replace('T', ' ').split('.')[0]}</div></td>
                                <td><span style="font-size:0.7rem; background:rgba(255,255,255,0.05); padding:2px 6px; border-radius:4px;">${h.profile}</span></td>
                                <td>
                                    <span class="risk-badge risk-high">${h.high}</span>
                                    <span class="risk-badge risk-medium" style="margin-left:5px;">${h.medium}</span>
                                </td>
                                <td>
                                    <div class="action-dropdown">
                                        <button style="background:none; border:1px solid var(--accent-primary); color:var(--accent-primary); padding:4px 8px; border-radius:4px; font-size:0.7rem;">Actions <i class="fas fa-caret-down"></i></button>
                                        <div class="action-dropdown-content">
                                            ${!h.is_scheduled ? `
                                                <button onclick="viewDetails('${h.scan_id}')"><i class="fas fa-search-plus"></i> Drill-down</button>
                                                <button onclick="relaunchScan('${h.target}', '${h.profile}')" style="color:var(--accent-primary);"><i class="fas fa-sync"></i> Relaunch Scan</button>
                                                ${h.status.toLowerCase().includes('error') ? `<button onclick="resumeScan('${h.scan_id}')" style="color:var(--warning);"><i class="fas fa-play-circle"></i> Resume Scan</button>` : ''}
                                                <button onclick="reschedule('${h.target}')"><i class="fas fa-calendar-alt"></i> Reschedule</button>
                                                <a href="/report?scan_id=${h.scan_id}&type=pdf"><i class="fas fa-file-pdf"></i> Download PDF</a>
                                                <a href="/report?scan_id=${h.scan_id}&type=excel"><i class="fas fa-file-excel"></i> Export Excel</a>
                                            ` : `
                                                <button onclick="cancelSchedule('${h.scan_id}')" style="color:var(--danger);"><i class="fas fa-trash-alt"></i> Cancel Job</button>
                                            `}
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        `;
                    });
                    document.getElementById("historyBody").innerHTML = html || "<tr><td colspan='5' style='text-align:center;'>No history</td></tr>";
                    updateChart(data);
                    updateStats(data);
                });
        }

        function viewDetails(scanId) {
            console.log("Fetching details for Scan ID:", scanId);
            axios.get(`/scan_result/${scanId}`).then(res => {
                console.log("Scan Result Data:", res.data);
                if (res.status === 202) {
                    alert(`Scan is still in progress (${res.data.status}). Progress: ${res.data.progress}%. Please wait for it to complete.`);
                    return;
                }
                const data = res.data;
                document.getElementById("drillDownTitle").innerText = `Scan Details: ${data.target}`;
                let html = "";
                
                if (!data.alerts || data.alerts.length === 0) {
                    html = "<div style='text-align:center; padding:2rem; opacity:0.6;'>No vulnerabilities identified in this scan.</div>";
                } else {
                    data.alerts.forEach(a => {
                        const r = (a.risk || 'Info').toLowerCase();
                        const i = a.risk === 'High' ? 'fas fa-exclamation-triangle' : (a.risk === 'Medium' ? 'fas fa-exclamation-circle' : 'fas fa-info-circle');
                        html += `
                            <div role="listitem" style="border-bottom:1px solid var(--glass-border); padding:1rem 0;">
                                <div style="display:flex; justify-content:space-between; align-items:center;">
                                    <h4 style="margin:0;"><i class="${i}" aria-hidden="true"></i> ${a.alert} ${a.is_zero_day ? '⚠️ <small style="color:var(--danger)">Zero-Day Heuristic Found</small>' : ''}</h4>
                                    <div style="text-align:right;">
                                        <span class="risk-badge risk-${r}">${a.risk}</span>
                                        <div style="font-size:0.7rem; color:var(--text-secondary); margin-top:2px;">Probable Exploitation: ${a.risk_score}%</div>
                                    </div>
                                </div>
                                <div style="margin:5px 0;">
                                    ${(a.intel || []).map(f => `<span style="font-size:0.65rem; background:rgba(239, 68, 68, 0.2); color:#ef4444; padding:2px 6px; border-radius:10px; margin-right:5px;">${f}</span>`).join('')}
                                </div>
                                <p style="font-size:0.8rem; color:var(--text-secondary); margin:0.5rem 0;">${a.description || 'N/A'}</p>
                                <div style="font-size:0.7rem; background:var(--bg-primary); padding:0.5rem; border-radius:0.5rem; margin-top:0.5rem;">
                                    <strong>Path:</strong> <code>${a.path}</code><br>
                                    <strong>Solution:</strong> ${a.solution || 'No fix suggested.'}
                                </div>
                                ${a.script ? `
                                    <div style="margin-top:0.5rem; font-size:0.75rem;">
                                        <strong>Auto-Remediation Script:</strong>
                                        <pre style="background:#000; color:#0f0; padding:0.5rem; border-radius:4px; overflow-x:auto; margin-top:5px;">${a.script}</pre>
                                    </div>
                                ` : ''}
                                ${a.cves && a.cves.length ? `<div style="margin-top:0.5rem; font-size:0.7rem;"><strong>CVEs:</strong> ${a.cves.map(c => `<a href="${c.href}" target="_blank" style="color:var(--accent-primary); margin-right:8px;">${c.id}</a>`).join('')}</div>` : ''}
                            </div>
                        `;
                    });
                }

                if (data.fixed && data.fixed.length > 0) {
                    html += `<div style="margin-top:2rem; padding:1rem; background:rgba(16, 185, 129, 0.1); border:1px solid var(--success); border-radius:12px;">
                        <h4 style="color:var(--success); margin:0 0 10px 0;">✅ Remediation Tracked (Fixed)</h4>
                        <ul style="margin:0; font-size:0.8rem; color:var(--text-secondary);">
                            ${data.fixed.map(f => `<li>${f}</li>`).join('')}
                        </ul>
                    </div>`;
                }

                document.getElementById("drillDownContent").innerHTML = html;
                document.getElementById("drillDownModal").style.display = "block";
            }).catch(e => {
                console.error(e);
                alert("Scan results not ready or error fetching.");
            });
        }

        function closeDrillDown() { document.getElementById("drillDownModal").style.display = "none"; }

        function reschedule(target) {
            document.getElementById("target").value = target;
            openSchedule();
        }

        function cancelSchedule(jobId) {
            if (!confirm("Stop this recurring scan?")) return;
            axios.post(`/cancel_schedule/${jobId}`).then(() => loadHistory());
        }

        function relaunchScan(target, profile) {
            document.getElementById("target").value = target;
            document.getElementById("scanProfile").value = profile || "deep";
            showSection('scan');
            startScan();
        }

        /* AUDIT LOGS */
        function loadAuditLogs() {
            document.getElementById("auditModal").style.display = "block";
            fetch("/admin/audit_logs")
                .then(res => res.json())
                .then(data => {
                    let html = "<table style='border-spacing: 0; width:100%;'><thead><tr><th style='background:var(--bg-secondary); padding:10px;'>User</th><th style='background:var(--bg-secondary);'>Action</th><th style='background:var(--bg-secondary);'>Details</th><th style='background:var(--bg-secondary);'>Date</th></tr></thead><tbody>";
                    data.forEach(log => {
                        html += `<tr>
                            <td style='padding:8px; border-bottom:1px solid var(--glass-border);'>${log.user}</td>
                            <td style='padding:8px; border-bottom:1px solid var(--glass-border); color:var(--accent-primary);'>${log.action}</td>
                            <td style='padding:8px; border-bottom:1px solid var(--glass-border);'>${log.details}</td>
                            <td style='padding:8px; border-bottom:1px solid var(--glass-border); color:var(--text-secondary);'>${log.date}</td>
                        </tr>`;
                    });
                    html += "</tbody></table>";
                    document.getElementById("auditList").innerHTML = html || "No activities logged";
                });
        }

        function loadErrorLogs() {
            document.getElementById("errorModal").style.display = "block";
            fetch("/admin/error_logs").then(res => res.json()).then(data => {
                if (!data || data.length === 0) {
                    document.getElementById("errorList").innerHTML = "<div style='text-align:center; padding:2rem; color:var(--text-secondary); opacity:0.6;'>✅ No scan errors detected in system logs.</div>";
                    return;
                }
                let h = "<table style='width:100%; border-collapse:collapse; font-size:0.75rem;'><thead><tr><th>Scan ID</th><th>Error</th><th>Date</th></tr></thead><tbody>";
                data.forEach(l => h += `<tr><td>${l.scan_id || 'N/A'}</td><td style="color:var(--danger)">${l.message}</td><td style="color:var(--text-secondary)">${l.date}</td></tr>`);
                document.getElementById("errorList").innerHTML = h + "</tbody></table>";
            });
        }
        function closeError() { document.getElementById("errorModal").style.display = "none"; }

        function resumeScan(scanId) {
            axios.post(`/resume/${scanId}`).then(res => {
                alert(res.data.message);
                loadSavedScans();
            });
        }


        /* I18N */
        const translations = {
            "en": { "start_scan": "Start Scan", "history": "History", "alerts": "Alerts", "assets": "Asset Inventory" },
            "uk_en": { "start_scan": "Commence Scan", "history": "Past Assessments", "alerts": "Vulnerabilities", "assets": "Asset Register" },
            "es": { "start_scan": "Iniciar Escaneo", "history": "Historial", "alerts": "Alertas", "assets": "Inventario" },
            "fr": { "start_scan": "Lancer le scan", "history": "Historique", "alerts": "Alertes", "assets": "Inventaire" },
            "de": { "start_scan": "Scan starten", "history": "Verlauf", "alerts": "Warnungen", "assets": "Inventar" },
            "pt": { "start_scan": "Iniciar Varredura", "history": "Histórico", "alerts": "Alertas", "assets": "Ativos" },
            "zh": { "start_scan": "开始扫描", "history": "历史记录", "alerts": "警报", "assets": "资产" },
            "ja": { "start_scan": "スキャン開始", "history": "履歴", "alerts": "アラート", "assets": "資産" },
            "ru": { "start_scan": "Начать сканирование", "history": "История", "alerts": "Оповещения", "assets": "Активы" },
            "ar": { "start_scan": "بدء الفحص", "history": "السجل", "alerts": "التنبيهات", "assets": "الأصول" },
            "it": { "start_scan": "Avvia scansione", "history": "Cronologia", "alerts": "Avvisi", "assets": "Asset" }
        };
        function changeLang() {
            const lang = document.getElementById("langSelect").value;
            localStorage.setItem("language", lang);
            applyLang(lang);
        }

        function applyLang(lang) {
            document.getElementById("langSelect").value = lang;
            document.querySelectorAll("[data-i18n]").forEach(el => {
                const key = el.getAttribute("data-i18n");
                el.innerText = translations[lang][key] || key;
            });
        }

        function closeAudit() {
            document.getElementById("auditModal").style.display = "none";
        }

        /* CHART SYSTEM */
        let myChart = null;
        function updateChart(data) {
            let h = 0, m = 0, l = 0;
            data.forEach(s => {
                if (!s.is_scheduled) {
                    h += s.high || 0;
                    med = (s.medium || 0); // Temporary fix for var name
                    m += med;
                    l += s.low || 0;
                }
            });

            document.getElementById("chartStats").innerHTML = `
                <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span>High Priority</span> <span style="color:var(--danger)">${h}</span></div>
                <div style="display:flex; justify-content:space-between; margin-bottom:5px;"><span>Medium Severity</span> <span style="color:var(--warning)">${m}</span></div>
                <div style="display:flex; justify-content:space-between;"><span>Low / Info</span> <span style="color:var(--success)">${l}</span></div>
            `;

            const ctx = document.getElementById('vulnChart').getContext('2d');
            if (myChart) myChart.destroy();

            myChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['High', 'Medium', 'Low'],
                    datasets: [{
                        data: [h, m, l],
                        backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                        borderWidth: 0,
                        hoverOffset: 12
                    }]
                },
                options: {
                    cutout: '75%',
                    plugins: { legend: { display: false } },
                    maintainAspectRatio: false,
                    animation: { animateRotate: true, duration: 1000 }
                }
            });
        }

        /* REPORT FIX */
        function downloadSingle(id, type) {
            window.open(`/report?scan_id=${id}&type=${type}`, "_blank");
        }

        function downloadReport(type) {
            let lastScan = Object.keys(currentScans).slice(-1)[0];
            if (!lastScan) {
                alert("No scan available");
                return;
            }
            window.open(`/report?scan_id=${lastScan}&type=${type}`, "_blank");
        }

        /* LOGOUT */
        function logout() {
            window.location.href = "/logout";
        }

        /* TERMINATE */
        function terminateScan(id) {
            if (!confirm("Are you sure you want to terminate this scan?")) return;

            axios.post(`/terminate/${id}`)
                .then(res => {
                    document.getElementById(`status_${id}`).innerText = "Terminated";
                    let card = document.getElementById(id);
                    if (card) {
                        let termBtn = card.querySelector(".terminate-btn");
                        if (termBtn) termBtn.style.display = 'none';
                    }
                })
                .catch(err => {
                    console.error(err);
                    alert("Error terminating scan");
                });
        }

        /* RESTORE ACTIVE SCANS AFTER REFRESH */
        function loadSavedScans() {
            fetch("/active_scans")
                .then(res => res.json())
                .then(data => {
                    Object.keys(data).forEach(id => {
                        let scan = data[id];
                        currentScans[id] = { target: scan.target };
                        createScanCard(id, scan.target);
                        pollScan(id);
                    });
                });
        }

        // Initial load handled by DOMContentLoaded

    