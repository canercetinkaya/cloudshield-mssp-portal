// CloudShield License Intelligence & Security Value Realization Portal Client Module
// Manages 5-Layer Reconciliation, Persona Analysis, SKU Inventory, Snapshot Diffing, and Upstream PDF Monitor

let currentLicenseSubTab = 'matrix';
let currentLicenseTenant = null;
let currentLicensePeriod = null;
let cachedLicenseData = null;

function initLicenseIntelligenceView() {
    populateLicenseTenantSelector();
    const sel = document.getElementById('licTenantSelect');
    if (sel && sel.value) {
        currentLicenseTenant = sel.value;
    } else {
        const topSel = document.getElementById('topTenantSelector');
        if (topSel && topSel.value && topSel.value !== 'ALL') {
            currentLicenseTenant = topSel.value;
            if (sel) sel.value = currentLicenseTenant;
        } else if (sel && sel.options.length > 0) {
            currentLicenseTenant = sel.options[0].value;
            sel.value = currentLicenseTenant;
        }
    }
    loadLicenseIntelligenceData();
}

function populateLicenseTenantSelector() {
    const sel = document.getElementById('licTenantSelect');
    if (!sel) return;
    const topSel = document.getElementById('topTenantSelector');
    if (!topSel) return;

    sel.innerHTML = '';
    for (let i = 0; i < topSel.options.length; i++) {
        const opt = topSel.options[i];
        if (opt.value !== 'ALL') {
            const newOpt = document.createElement('option');
            newOpt.value = opt.value;
            newOpt.textContent = opt.textContent;
            sel.appendChild(newOpt);
        }
    }
}

function onLicenseTenantChange() {
    const sel = document.getElementById('licTenantSelect');
    if (sel) {
        currentLicenseTenant = sel.value;
        loadLicenseIntelligenceData();
    }
}

function switchLicenseSubTab(subTab) {
    currentLicenseSubTab = subTab;
    const tabs = ['matrix', 'inventory', 'personas', 'smb_azure', 'diff', 'catalog_feed'];
    tabs.forEach(t => {
        const view = document.getElementById(`licView-${t}`);
        const btn = document.getElementById(`licBtn-${t}`);
        if (view) view.classList.add('hidden');
        if (btn) {
            btn.classList.remove('bg-ks-navy', 'text-white', 'shadow');
            btn.classList.add('text-slate-600', 'hover:bg-slate-100');
        }
    });

    const activeView = document.getElementById(`licView-${subTab}`);
    const activeBtn = document.getElementById(`licBtn-${subTab}`);
    if (activeView) activeView.classList.remove('hidden');
    if (activeBtn) {
        activeBtn.classList.add('bg-ks-navy', 'text-white', 'shadow');
        activeBtn.classList.remove('text-slate-600', 'hover:bg-slate-100');
    }
}

function loadLicenseIntelligenceData() {
    if (!currentLicenseTenant) return;
    const tok = localStorage.getItem('token') || '';
    const headers = { 'Authorization': `Bearer ${tok}` };

    const loader = document.getElementById('licLoadingIndicator');
    if (loader) loader.classList.remove('hidden');

    Promise.all([
        fetch(`/api/licenses/value-summary?tenantId=${encodeURIComponent(currentLicenseTenant)}`, { headers }).then(r => r.json()),
        fetch(`/api/licenses/reconciliation?tenantId=${encodeURIComponent(currentLicenseTenant)}`, { headers }).then(r => r.json()),
        fetch(`/api/licenses/inventory?tenantId=${encodeURIComponent(currentLicenseTenant)}`, { headers }).then(r => r.json()),
        fetch(`/api/licenses/users?tenantId=${encodeURIComponent(currentLicenseTenant)}`, { headers }).then(r => r.json()),
        fetch(`/api/licenses/catalog/feed-status`, { headers }).then(r => r.json())
    ]).then(([resSummary, resRecs, resInv, resUsers, resFeed]) => {
        if (loader) loader.classList.add('hidden');

        const summary = resSummary.success ? resSummary.summary : {};
        const reconciliations = resRecs.success ? resRecs.reconciliations : [];
        const inventory = resInv.success ? resInv.inventory : [];
        const users = resUsers.success ? resUsers.users : [];
        const feed = resFeed.success ? resFeed.feedStatus : {};

        cachedLicenseData = { summary, reconciliations, inventory, users, feed };

        renderLicenseKpis(summary);
        renderWorkloadMatrix(reconciliations);
        renderLicenseInventory(inventory);
        renderUserPersonas(users);
        renderSmbAndAzure(summary, inventory);
        renderFeedMonitor(feed);
        loadLicenseSnapshots();
    }).catch(err => {
        if (loader) loader.classList.add('hidden');
        console.error('License data fetch failed:', err);
    });
}

function renderLicenseKpis(summary) {
    summary = summary || {};
    const total = summary.total_licenses || 0;
    const assigned = summary.assigned_licenses || 0;
    const idle = summary.idle_licenses || 0;
    const valIndex = summary.overall_value_index || 0.0;
    const duplicates = summary.duplicate_entitlement_users || 0;
    const inactives = summary.inactive_licensed_users || 0;
    const isLive = summary.is_live;

    document.getElementById('licKpiTotal').textContent = total;
    document.getElementById('licKpiAssigned').textContent = assigned;
    document.getElementById('licKpiIdle').textContent = idle;
    document.getElementById('licKpiValueIndex').textContent = `%${valIndex}`;
    document.getElementById('licKpiDuplicates').textContent = duplicates;
    document.getElementById('licKpiInactive').textContent = inactives;

    const banner = document.getElementById('licSyntheticBanner');
    if (banner) {
        if (isLive) {
            banner.classList.add('hidden');
        } else {
            banner.classList.remove('hidden');
        }
    }
}

function renderWorkloadMatrix(reconciliations) {
    const tbody = document.getElementById('licMatrixTbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!reconciliations || reconciliations.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-slate-400">Veri bulunamadı. Analiz çalıştırınız.</td></tr>`;
        return;
    }

    reconciliations.forEach(r => {
        const st = r.realization_status || '';
        let badgeColor = 'bg-rose-100 text-rose-800 border-rose-300';
        if (st.includes('Tam Değer') || st.includes('Doğrulandı')) {
            badgeColor = 'bg-emerald-100 text-emerald-800 border-emerald-300';
        } else if (st.includes('Bekleniyor') || st.includes('Boşta')) {
            badgeColor = 'bg-amber-100 text-amber-800 border-amber-300';
        }

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-50 transition border-b border-slate-100';
        tr.innerHTML = `
            <td class="py-3 px-3">
                <div class="font-bold text-slate-800 text-xs">${r.workload_name}</div>
                <div class="text-[10px] text-slate-400 font-mono">${r.workload_code}</div>
            </td>
            <td class="text-right py-3 px-3 font-semibold text-slate-700">${r.entitlement_count}</td>
            <td class="text-right py-3 px-3 font-semibold text-blue-600">${r.assignment_count}</td>
            <td class="text-right py-3 px-3 text-slate-600">${r.service_plan_active_count}</td>
            <td class="text-right py-3 px-3 text-slate-600">${r.configuration_active_count}</td>
            <td class="text-right py-3 px-3 font-bold text-emerald-600">${r.telemetry_active_count}</td>
            <td class="py-3 px-3">
                <span class="inline-block px-2 py-0.5 text-[11px] font-bold rounded-full border ${badgeColor}">${st}</span>
            </td>
            <td class="py-3 px-3 text-xs text-slate-600 max-w-xs">${r.gap_description || '-'}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderLicenseInventory(inventory) {
    const tbody = document.getElementById('licInventoryTbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!inventory || inventory.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400">Envanter bulunamadı.</td></tr>`;
        return;
    }

    inventory.forEach(item => {
        const prepaid = item.prepaid_units || 0;
        const consumed = item.consumed_units || 0;
        const idle = Math.max(0, prepaid - consumed);
        const pct = prepaid > 0 ? Math.round((consumed / prepaid) * 100) : 0;

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-50 transition border-b border-slate-100';
        tr.innerHTML = `
            <td class="py-3 px-3 font-bold text-slate-800">${item.display_name}</td>
            <td class="py-3 px-3 font-mono text-xs text-slate-600"><code>${item.sku_part_number}</code></td>
            <td class="text-right py-3 px-3 font-semibold text-slate-700">${prepaid}</td>
            <td class="text-right py-3 px-3 font-bold text-blue-600">${consumed}</td>
            <td class="text-right py-3 px-3 font-bold ${idle > 0 ? 'text-amber-600' : 'text-emerald-600'}">${idle}</td>
            <td class="text-right py-3 px-3">
                <div class="flex items-center justify-end space-x-2">
                    <span class="text-xs font-semibold text-slate-700">%${pct}</span>
                    <div class="w-16 bg-slate-200 rounded-full h-1.5 overflow-hidden">
                        <div class="bg-blue-600 h-1.5" style="width: ${pct}%"></div>
                    </div>
                </div>
            </td>
            <td class="text-center py-3 px-3">
                <span class="inline-block px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-100 text-emerald-800">${item.capability_status}</span>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function renderUserPersonas(users, filterType) {
    const tbody = document.getElementById('licPersonasTbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    let filtered = users || [];
    if (filterType === 'duplicate') {
        filtered = filtered.filter(u => u.value_status === 'Mükerrer veya Çakışan Lisans Hakkı');
    } else if (filterType === 'inactive_licensed') {
        filtered = filtered.filter(u => !u.account_enabled && (u.assigned_skus && u.assigned_skus.length > 0));
    } else if (filterType === 'unlicensed_active') {
        filtered = filtered.filter(u => u.account_enabled && (!u.assigned_skus || u.assigned_skus.length === 0));
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-400">Seçilen filtrede kullanıcı bulunamadı.</td></tr>`;
        return;
    }

    filtered.forEach(u => {
        const skusStr = (u.assigned_skus || []).map(s => s.sku_part_number).join(', ') || 'Lisans Yok';
        const risks = (u.risk_indicators || []).join('<br>');
        const recs = (u.recommendations || []).join('<br>');

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-50 transition border-b border-slate-100';
        tr.innerHTML = `
            <td class="py-2.5 px-3 font-semibold text-slate-800">
                <div>${u.user_principal_name}</div>
                <div class="text-[10px] text-slate-400">${u.job_title || ''} &bull; ${u.department || ''}</div>
            </td>
            <td class="py-2.5 px-3">
                <span class="inline-block px-2 py-0.5 text-[10px] font-bold rounded bg-slate-100 text-slate-700 border border-slate-200">${u.persona_type}</span>
            </td>
            <td class="py-2.5 px-3 font-mono text-xs text-blue-700">${skusStr}</td>
            <td class="py-2.5 px-3 text-xs text-rose-600">${risks || '<span class="text-emerald-600 font-semibold">&#10003; Normal</span>'}</td>
            <td class="py-2.5 px-3 text-xs text-slate-600">${recs || '-'}</td>
            <td class="text-center py-2.5 px-3">
                <span class="inline-block px-2 py-0.5 text-[10px] font-bold rounded ${u.account_enabled ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}">
                    ${u.account_enabled ? 'Aktif' : 'Devre Dışı'}
                </span>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterUserPersonas(type) {
    if (!cachedLicenseData || !cachedLicenseData.users) return;
    renderUserPersonas(cachedLicenseData.users, type);
}

function renderSmbAndAzure(summary, inventory) {
    const smbBox = document.getElementById('licSmbCapBox');
    const smbUnits = document.getElementById('licSmbUnits');
    const smbMsg = document.getElementById('licSmbMessage');

    if (smbUnits && smbMsg) {
        smbUnits.textContent = `${summary.smb_units || 0} / 300`;
        smbMsg.textContent = summary.smb_message || 'KOBİ lisans sınırları kontrol edilmektedir.';
    }
}

function renderFeedMonitor(feed) {
    const lastCheck = document.getElementById('licFeedLastCheck');
    const nextCheck = document.getElementById('licFeedNextCheck');
    const entStatus = document.getElementById('licFeedEntStatus');
    const smbStatus = document.getElementById('licFeedSmbStatus');

    if (lastCheck) lastCheck.textContent = feed.last_checked_at ? new Date(feed.last_checked_at).toLocaleString('tr-TR') : 'Henüz Kontrol Edilmedi';
    if (nextCheck) nextCheck.textContent = feed.next_scheduled_check ? new Date(feed.next_scheduled_check).toLocaleString('tr-TR') : '30 Gün Sonra';

    const sources = feed.sources || {};
    if (entStatus) {
        const ent = sources.enterprise_comparison || {};
        entStatus.textContent = ent.last_status || 'Doğrulandı';
    }
    if (smbStatus) {
        const smb = sources.smb_comparison || {};
        smbStatus.textContent = smb.last_status || 'Doğrulandı';
    }
}

function loadLicenseSnapshots() {
    if (!currentLicenseTenant) return;
    const tok = localStorage.getItem('token') || '';
    const headers = { 'Authorization': `Bearer ${tok}` };

    fetch(`/api/licenses/snapshots?tenantId=${encodeURIComponent(currentLicenseTenant)}`, { headers })
        .then(r => r.json())
        .then(res => {
            const listEl = document.getElementById('licSnapshotsList');
            if (!listEl) return;
            listEl.innerHTML = '';
            const snaps = res.snapshots || [];
            if (snaps.length === 0) {
                listEl.innerHTML = '<li class="text-slate-400 text-xs py-2">Kayıtlı snapshot bulunamadı.</li>';
                return;
            }
            snaps.forEach(s => {
                const li = document.createElement('li');
                li.className = 'flex justify-between items-center py-2 border-b border-slate-100 text-xs';
                li.innerHTML = `
                    <span class="font-bold text-slate-800">${s.period}</span>
                    <span class="text-slate-500 font-mono text-[10px]">${s.snapshot_date}</span>
                    <button onclick="compareWithPeriod('${s.period}')" class="text-xs text-ks-red hover:underline font-semibold">Farkı İncele (Diff)</button>
                `;
                listEl.appendChild(li);
            });
        });
}

function triggerLicenseCollection(dryRun) {
    if (!currentLicenseTenant) return;
    const tok = localStorage.getItem('token') || '';
    const headers = { 'Authorization': `Bearer ${tok}`, 'Content-Type': 'application/json' };

    const btn = document.getElementById('licRunCollectBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1"></i> Analiz Çalıştırılıyor...`;
    }

    fetch('/api/licenses/collect', {
        method: 'POST',
        headers,
        body: JSON.stringify({ tenantId: currentLicenseTenant, dryRun: dryRun })
    })
    .then(r => r.json())
    .then(res => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-play mr-1"></i> Lisans Analizi Başlat`;
        }
        if (res.success) {
            alert('Lisans Zekâsı ve Değer Gerçekleştirme analizi başarıyla tamamlandı.');
            loadLicenseIntelligenceData();
        } else {
            alert(`Hata: ${res.error || 'Analiz başarısız'}`);
        }
    })
    .catch(err => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-play mr-1"></i> Lisans Analizi Başlat`;
        }
        alert(`Sunucu iletişim hatası: ${err}`);
    });
}

function checkUpstreamPdfUpdates() {
    const tok = localStorage.getItem('token') || '';
    const headers = { 'Authorization': `Bearer ${tok}`, 'Content-Type': 'application/json' };

    fetch('/api/licenses/catalog/check-updates', {
        method: 'POST',
        headers,
        body: JSON.stringify({ force: true })
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            alert('Microsoft resmi PDF karşılaştırma dokümanları kontrol edildi. Katalog günceldir.');
            loadLicenseIntelligenceData();
        } else {
            alert(`Kontrol hatası: ${res.error}`);
        }
    });
}

function previewLicenseReport() {
    if (!currentLicenseTenant) return;
    const url = `/api/licenses/report/html?tenantId=${encodeURIComponent(currentLicenseTenant)}`;
    window.open(url, '_blank');
}

function downloadLicensePdf() {
    if (!currentLicenseTenant) return;
    const url = `/api/licenses/report/pdf?tenantId=${encodeURIComponent(currentLicenseTenant)}`;
    window.open(url, '_blank');
}
