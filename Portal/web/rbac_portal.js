// CloudShield MSSP Platform - Client-Side RBAC & Authorization Management Module
// Powers the 11 Administration Views:
// 1. Authorization Dashboard
// 2. Customers
// 3. Services
// 4. Customer Service Matrix
// 5. Teams
// 6. Role Catalog
// 7. Permission Catalog
// 8. Access Assignments
// 9. Access Reviews (PIM Approvals)
// 10. Authorization Audit
// 11. Effective Access Simulator

let currentRbacSubTab = 'dash';
let cachedRbacUsers = [];
let cachedRbacCustomers = [];
let cachedRbacServices = [];
let cachedRbacRoles = [];

function initRbacPortal() {
    switchRbacSubTab(currentRbacSubTab || 'dash');
    loadRbacAuxData();
}

function loadRbacAuxData() {
    const tok = localStorage.getItem('token') || '';
    const headers = { 'Authorization': `Bearer ${tok}` };

    fetch('/api/rbac/users', { headers })
        .then(r => r.json())
        .then(res => { if (res.success) cachedRbacUsers = res.data; });

    fetch('/api/rbac/customers', { headers })
        .then(r => r.json())
        .then(res => { if (res.success) cachedRbacCustomers = res.data; });

    fetch('/api/rbac/services', { headers })
        .then(r => r.json())
        .then(res => { if (res.success) cachedRbacServices = res.data; });

    fetch('/api/rbac/roles', { headers })
        .then(r => r.json())
        .then(res => { if (res.success) cachedRbacRoles = res.data; });
}

function switchRbacSubTab(subTabId) {
    currentRbacSubTab = subTabId;
    const subTabs = ['dash', 'customers', 'services', 'matrix', 'teams', 'roles', 'perms', 'assignments', 'approvals', 'audit', 'simulator'];
    
    subTabs.forEach(s => {
        const view = document.getElementById(`rbacView-${s}`);
        const btn = document.getElementById(`rbacBtn-${s}`);
        if (view) view.classList.add('hidden');
        if (btn) {
            btn.classList.remove('bg-ks-navy', 'text-white', 'shadow');
            btn.classList.add('text-slate-600', 'hover:bg-slate-100');
        }
    });

    const activeView = document.getElementById(`rbacView-${subTabId}`);
    const activeBtn = document.getElementById(`rbacBtn-${subTabId}`);
    if (activeView) activeView.classList.remove('hidden');
    if (activeBtn) {
        activeBtn.classList.add('bg-ks-navy', 'text-white', 'shadow');
        activeBtn.classList.remove('text-slate-600', 'hover:bg-slate-100');
    }

    if (subTabId === 'dash') loadRbacDashboard();
    else if (subTabId === 'customers') loadRbacCustomers();
    else if (subTabId === 'services') loadRbacServices();
    else if (subTabId === 'matrix') loadRbacMatrix();
    else if (subTabId === 'teams') loadRbacTeams();
    else if (subTabId === 'roles') loadRbacRoles();
    else if (subTabId === 'perms') loadRbacPermissions();
    else if (subTabId === 'assignments') loadRbacAssignments();
    else if (subTabId === 'approvals') loadRbacApprovals();
    else if (subTabId === 'audit') loadRbacAudit();
    else if (subTabId === 'simulator') prepareSimulatorUI();
}

// 1. Dashboard View
function loadRbacDashboard() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/dashboard', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const d = res.data;
            document.getElementById('rbacStatUsers').textContent = `${d.activeUsers} / ${d.totalUsers}`;
            document.getElementById('rbacStatAssignments').textContent = d.activeAssignments;
            document.getElementById('rbacStatPending').textContent = d.pendingApprovals;
            document.getElementById('rbacStatAuditAllow').textContent = d.auditStats24h.allow;
            document.getElementById('rbacStatAuditDeny').textContent = d.auditStats24h.deny;
        })
        .catch(err => console.error('Dashboard load error:', err));
}

// 2. Customers View
function loadRbacCustomers() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/customers', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            cachedRbacCustomers = res.data;
            const tbody = document.getElementById('rbacCustomersTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(c => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                    <td class="py-3 px-4 font-mono text-xs font-bold text-ks-navy">${c.id}</td>
                    <td class="py-3 px-4 font-semibold text-xs text-slate-800">${c.name}</td>
                    <td class="py-3 px-4 font-mono text-[11px] text-slate-500">${c.tenant_id}</td>
                    <td class="py-3 px-4 text-xs text-slate-600">${c.contact_email}</td>
                    <td class="py-3 px-4 text-xs font-bold text-center">
                        <span class="bg-blue-50 text-blue-700 px-2 py-0.5 rounded-full border border-blue-200">${c.active_service_count || 0} Aktif</span>
                    </td>
                    <td class="py-3 px-4 text-xs font-bold text-center">
                        <span class="bg-emerald-50 text-emerald-700 px-2 py-0.5 rounded-full border border-emerald-200">${c.secure_score || 0}%</span>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <span class="px-2 py-0.5 text-[10px] font-bold rounded-full ${c.connection_status === 'LiveConnected' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'}">
                            ${c.connection_status}
                        </span>
                    </td>
                </tr>
            `).join('');
        });
}

// 3. Services View
function loadRbacServices() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/services', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            cachedRbacServices = res.data;
            const tbody = document.getElementById('rbacServicesTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(s => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                    <td class="py-3 px-4 font-mono text-xs font-bold text-ks-navy">${s.code}</td>
                    <td class="py-3 px-4 text-xs font-semibold text-slate-800">${s.name_tr}</td>
                    <td class="py-3 px-4 text-xs text-slate-500">${s.name_en}</td>
                    <td class="py-3 px-4 text-xs font-bold">
                        <span class="bg-slate-100 text-slate-700 px-2 py-0.5 rounded">${s.category}</span>
                    </td>
                    <td class="py-3 px-4 text-xs text-slate-600">${s.product_family}</td>
                    <td class="py-3 px-4 font-mono text-[11px] text-slate-400">${s.plugin_folder || '-'}</td>
                    <td class="py-3 px-4 text-center">
                        <span class="px-2 py-0.5 text-[10px] font-bold rounded-full ${s.is_active ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}">
                            ${s.is_active ? 'Aktif' : 'Devre Dışı'}
                        </span>
                    </td>
                </tr>
            `).join('');
        });
}

// 4. Customer Service Matrix View
function loadRbacMatrix() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/customer-services', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const tbody = document.getElementById('rbacMatrixTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(m => {
                let statusBadge = '';
                if (m.status === 'Onboarded') statusBadge = '<span class="bg-emerald-100 text-emerald-800 border border-emerald-300 text-[10px] font-bold px-2 py-0.5 rounded-full"><i class="fa-solid fa-check mr-1"></i>Onboarded</span>';
                else if (m.status === 'Suspended') statusBadge = '<span class="bg-amber-100 text-amber-800 border border-amber-300 text-[10px] font-bold px-2 py-0.5 rounded-full"><i class="fa-solid fa-pause mr-1"></i>Suspended</span>';
                else statusBadge = '<span class="bg-slate-100 text-slate-600 border border-slate-300 text-[10px] font-bold px-2 py-0.5 rounded-full"><i class="fa-solid fa-ban mr-1"></i>Disabled</span>';

                return `
                    <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                        <td class="py-3 px-4 text-xs font-bold text-ks-navy">${m.customer_name} <span class="text-[10px] text-slate-400 font-mono">(${m.customer_id})</span></td>
                        <td class="py-3 px-4 text-xs font-semibold text-slate-800"><span class="font-mono text-ks-red font-bold">${m.service_code}</span> - ${m.service_name}</td>
                        <td class="py-3 px-4 text-xs"><span class="bg-blue-50 text-blue-700 px-2 py-0.5 rounded font-medium">${m.service_level}</span></td>
                        <td class="py-3 px-4 text-center">${statusBadge}</td>
                        <td class="py-3 px-4 text-right space-x-1">
                            ${m.status !== 'Onboarded' ? `
                                <button onclick="setMatrixServiceStatus('${m.customer_id}', '${m.service_id}', 'onboard')" class="text-[11px] bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-300 font-bold px-2 py-1 rounded transition">Aktif Et</button>
                            ` : ''}
                            ${m.status === 'Onboarded' ? `
                                <button onclick="setMatrixServiceStatus('${m.customer_id}', '${m.service_id}', 'suspend')" class="text-[11px] bg-amber-50 text-amber-700 hover:bg-amber-100 border border-amber-300 font-bold px-2 py-1 rounded transition">Askıya Al</button>
                                <button onclick="setMatrixServiceStatus('${m.customer_id}', '${m.service_id}', 'disable')" class="text-[11px] bg-red-50 text-red-700 hover:bg-red-100 border border-red-300 font-bold px-2 py-1 rounded transition">Devre Dışı</button>
                            ` : ''}
                        </td>
                    </tr>
                `;
            }).join('');
        });
}

function setMatrixServiceStatus(customerId, serviceId, action) {
    const tok = localStorage.getItem('token') || '';
    fetch(`/api/rbac/customer-services/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tok}` },
        body: jsonSafeStringify({ customerId, serviceId })
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            loadRbacMatrix();
        } else {
            alert(`İşlem Başarısız: ${res.error}`);
        }
    });
}

// 5. Teams View
function loadRbacTeams() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/teams', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const container = document.getElementById('rbacTeamsContainer');
            if (!container) return;
            container.innerHTML = res.data.map(t => `
                <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-3">
                    <div class="flex items-center justify-between border-b border-slate-100 pb-3">
                        <div>
                            <h3 class="font-bold text-sm text-ks-navy">${t.name}</h3>
                            <p class="text-xs text-slate-500">${t.description || ''}</p>
                        </div>
                        <span class="bg-ks-navy/10 text-ks-navy font-bold text-xs px-2.5 py-1 rounded-full">${t.memberCount} Üye</span>
                    </div>
                    <div class="space-y-1.5 max-h-48 overflow-y-auto">
                        ${t.members.map(m => `
                            <div class="flex items-center justify-between text-xs bg-slate-50 p-2 rounded border border-slate-100">
                                <div>
                                    <span class="font-semibold text-slate-800">${m.display_name}</span>
                                    <span class="text-[10px] text-slate-400 font-mono block">${m.upn}</span>
                                </div>
                                <span class="text-[10px] font-bold bg-blue-100 text-blue-800 px-1.5 py-0.5 rounded">${m.role_in_team}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('');
        });
}

// 6. Role Catalog View
function loadRbacRoles() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/roles', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            cachedRbacRoles = res.data;
            const tbody = document.getElementById('rbacRolesTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(r => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                    <td class="py-3 px-4 font-mono text-xs font-bold text-ks-navy">${r.name}</td>
                    <td class="py-3 px-4 text-xs font-semibold text-slate-800">${r.display_name}</td>
                    <td class="py-3 px-4 text-xs text-slate-600">${r.description}</td>
                    <td class="py-3 px-4 text-center">
                        <span class="px-2 py-0.5 text-[10px] font-bold rounded-full ${r.is_platform_role ? 'bg-purple-100 text-purple-800' : 'bg-slate-100 text-slate-700'}">
                            ${r.is_platform_role ? 'Global Platform' : 'Kapsamlı'}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-center font-bold text-xs text-blue-700">
                        <span class="bg-blue-50 border border-blue-200 px-2 py-0.5 rounded-full">${r.permissions.length} İzin</span>
                    </td>
                    <td class="py-3 px-4 text-center font-bold text-xs text-slate-700">${r.assignedUserCount} Kullanıcı</td>
                </tr>
            `).join('');
        });
}

// 7. Permission Catalog View
function loadRbacPermissions() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/permissions', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const tbody = document.getElementById('rbacPermsTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(p => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                    <td class="py-3 px-4 font-mono text-xs font-bold text-ks-red">${p.code}</td>
                    <td class="py-3 px-4 text-xs font-semibold text-slate-800">${p.name}</td>
                    <td class="py-3 px-4 text-xs">
                        <span class="bg-slate-100 text-slate-700 px-2 py-0.5 rounded uppercase font-bold text-[10px]">${p.domain}</span>
                    </td>
                    <td class="py-3 px-4 text-xs text-slate-600">${p.description}</td>
                </tr>
            `).join('');
        });
}

// 8. Access Assignments View
function loadRbacAssignments() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/assignments', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const tbody = document.getElementById('rbacAssignmentsTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(a => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition ${!a.is_active ? 'opacity-50' : ''}">
                    <td class="py-3 px-4 text-xs font-bold text-slate-800">
                        <span class="bg-slate-100 text-slate-600 text-[10px] px-1.5 py-0.5 rounded mr-1 font-mono">${a.subject_type}</span>
                        ${a.subject_name}
                    </td>
                    <td class="py-3 px-4 text-xs font-semibold text-ks-navy">${a.role_display || a.role_name}</td>
                    <td class="py-3 px-4 text-xs">
                        <span class="px-2 py-0.5 rounded text-[11px] font-bold ${a.customer_scope === 'ALL' ? 'bg-purple-100 text-purple-800' : 'bg-blue-50 text-blue-700'}">
                            ${a.customer_scope === 'ALL' ? '🌐 Tüm Müşteriler' : (a.customer_name || a.customer_id)}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-xs">
                        <span class="px-2 py-0.5 rounded text-[11px] font-bold ${a.service_scope === 'ALL' ? 'bg-purple-100 text-purple-800' : 'bg-emerald-50 text-emerald-700'}">
                            ${a.service_scope === 'ALL' ? '⚡ Tüm Servisler' : (a.service_code || a.service_id)}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-xs text-slate-500">
                        ${a.is_temporary ? `<span class="text-amber-600 font-bold"><i class="fa-solid fa-clock mr-1"></i>${a.valid_to ? a.valid_to.slice(0,16) : 'Süreli'}</span>` : '<span class="text-slate-400">Kalıcı</span>'}
                    </td>
                    <td class="py-3 px-4 text-center">
                        <span class="px-2 py-0.5 text-[10px] font-bold rounded-full ${a.is_active ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}">
                            ${a.is_active ? 'Aktif' : 'İptal Edildi'}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-right">
                        ${a.is_active ? `
                            <button onclick="revokeRbacAssignment('${a.id}')" class="text-xs text-red-600 hover:text-red-800 font-bold bg-red-50 hover:bg-red-100 px-2.5 py-1 rounded transition border border-red-200">
                                <i class="fa-solid fa-trash-can mr-1"></i>İptal Et
                            </button>
                        ` : '<span class="text-[10px] text-slate-400">Pasif</span>'}
                    </td>
                </tr>
            `).join('');
        });
}

function revokeRbacAssignment(asgnId) {
    if (!confirm('Bu erişim atamasını iptal etmek (revoke) istediğinize emin misiniz?')) return;
    const tok = localStorage.getItem('token') || '';
    fetch(`/api/rbac/assignments/${asgnId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${tok}` }
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            loadRbacAssignments();
        } else {
            alert(`İptal Başarısız: ${res.error}`);
        }
    });
}

// 9. Access Reviews & PIM Approvals View
function loadRbacApprovals() {
    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/approvals', { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const tbody = document.getElementById('rbacApprovalsTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(ap => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                    <td class="py-3 px-4 text-xs font-bold text-slate-800">
                        ${ap.requester_name}
                        <span class="block text-[10px] text-slate-400 font-mono">${ap.requester_upn}</span>
                    </td>
                    <td class="py-3 px-4 text-xs font-bold text-ks-navy">${ap.role_display || ap.role_name}</td>
                    <td class="py-3 px-4 text-xs text-slate-600">${ap.customer_name || 'Tüm Müşteriler'} / ${ap.service_code || 'Tüm Servisler'}</td>
                    <td class="py-3 px-4 text-xs font-semibold text-slate-700">${ap.duration_hours} Saat</td>
                    <td class="py-3 px-4 text-xs text-slate-500 max-w-xs truncate" title="${ap.reason}">${ap.reason}</td>
                    <td class="py-3 px-4 text-center">
                        <span class="px-2 py-0.5 text-[10px] font-bold rounded-full ${ap.status === 'Approved' ? 'bg-emerald-100 text-emerald-800' : (ap.status === 'Rejected' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800')}">
                            ${ap.status}
                        </span>
                    </td>
                    <td class="py-3 px-4 text-right space-x-1">
                        ${ap.status === 'Pending' ? `
                            <button onclick="decideRbacApproval('${ap.id}', 'Approved')" class="text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-bold px-2.5 py-1 rounded transition shadow-sm">Onayla</button>
                            <button onclick="decideRbacApproval('${ap.id}', 'Rejected')" class="text-xs bg-red-600 hover:bg-red-700 text-white font-bold px-2.5 py-1 rounded transition shadow-sm">Reddet</button>
                        ` : `<span class="text-[11px] text-slate-400">${ap.approver_name || '-'}</span>`}
                    </td>
                </tr>
            `).join('');
        });
}

function decideRbacApproval(approvalId, decision) {
    const reason = prompt(`Onay gerekçesi giriniz (${decision}):`, decision === 'Approved' ? 'Yönetici onayladı' : 'Uygun görülmedi');
    if (reason === null) return;
    const tok = localStorage.getItem('token') || '';
    fetch(`/api/rbac/approvals/${approvalId}/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tok}` },
        body: jsonSafeStringify({ decision, reason })
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            loadRbacApprovals();
        } else {
            alert(`Hata: ${res.error}`);
        }
    });
}

// 10. Authorization Audit Log View
function loadRbacAudit() {
    const tok = localStorage.getItem('token') || '';
    const decision = document.getElementById('rbacAuditDecisionFilter')?.value || '';
    const type = document.getElementById('rbacAuditTypeFilter')?.value || '';

    const url = `/api/rbac/audit?limit=100&decision=${encodeURIComponent(decision)}&type=${encodeURIComponent(type)}`;
    fetch(url, { headers: { 'Authorization': `Bearer ${tok}` } })
        .then(r => r.json())
        .then(res => {
            if (!res.success) return;
            const tbody = document.getElementById('rbacAuditTbody');
            if (!tbody) return;
            tbody.innerHTML = res.data.map(ev => `
                <tr class="border-b border-slate-100 hover:bg-slate-50 transition">
                    <td class="py-2.5 px-4 font-mono text-[11px] text-slate-500">${ev.timestamp.replace('T', ' ').slice(0, 19)}</td>
                    <td class="py-2.5 px-4 font-bold text-xs text-ks-navy">${ev.user_upn || 'Anonymous'}</td>
                    <td class="py-2.5 px-4 font-mono text-xs font-semibold text-slate-700">${ev.event_type}</td>
                    <td class="py-2.5 px-4 font-mono text-[11px] text-slate-500 truncate max-w-xs" title="${ev.resource}">${ev.resource}</td>
                    <td class="py-2.5 px-4 text-center font-bold">
                        <span class="px-2 py-0.5 rounded-full text-[10px] ${ev.decision === 'ALLOW' ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-red-100 text-red-800 border border-red-300'}">
                            ${ev.decision}
                        </span>
                    </td>
                    <td class="py-2.5 px-4 text-xs text-slate-600 max-w-md truncate" title="${ev.reason || ''}">${ev.reason || '-'}</td>
                    <td class="py-2.5 px-4 font-mono text-[10px] text-slate-400">${ev.ip_address}</td>
                </tr>
            `).join('');
        });
}

// 11. Effective Access Simulator View
function prepareSimulatorUI() {
    const userSel = document.getElementById('simUserSelect');
    const custSel = document.getElementById('simCustomerSelect');
    const svcsContainer = document.getElementById('simServicesContainer');

    if (userSel && cachedRbacUsers.length > 0) {
        userSel.innerHTML = cachedRbacUsers.map(u => `
            <option value="${u.id}">${u.display_name} (${u.upn})</option>
        `).join('');
    }

    if (custSel && cachedRbacCustomers.length > 0) {
        custSel.innerHTML = `
            <option value="">🌐 Global (Tüm Müşteriler)</option>
            ${cachedRbacCustomers.map(c => `<option value="${c.id}">${c.name} (${c.id})</option>`).join('')}
        `;
    }

    if (svcsContainer && cachedRbacServices.length > 0) {
        svcsContainer.innerHTML = cachedRbacServices.map(s => `
            <label class="flex items-center space-x-2 text-xs bg-slate-50 border border-slate-200 p-2 rounded cursor-pointer hover:bg-slate-100">
                <input type="checkbox" name="simServiceCheckbox" value="${s.code}" class="rounded text-ks-red focus:ring-ks-red">
                <span class="font-bold text-ks-navy">${s.code}</span>
                <span class="text-slate-500 truncate text-[11px]">${s.name_tr}</span>
            </label>
        `).join('');
    }
}

function runAccessSimulation() {
    const userId = document.getElementById('simUserSelect').value;
    const customerId = document.getElementById('simCustomerSelect').value || null;
    const permission = document.getElementById('simPermissionSelect').value;
    
    const checkboxes = document.querySelectorAll('input[name="simServiceCheckbox"]:checked');
    const serviceIds = Array.from(checkboxes).map(cb => cb.value);

    const tok = localStorage.getItem('token') || '';
    fetch('/api/rbac/simulator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tok}` },
        body: jsonSafeStringify({ userId, customerId, serviceIds, permission })
    })
    .then(r => r.json())
    .then(res => {
        if (!res.success) {
            alert(`Simülasyon Hatası: ${res.error}`);
            return;
        }

        const data = res.data;
        const resultCard = document.getElementById('simResultCard');
        resultCard.classList.remove('hidden');

        const banner = document.getElementById('simDecisionBanner');
        if (data.decision === 'ALLOW') {
            banner.className = 'p-4 rounded-xl border border-emerald-300 bg-emerald-50 text-emerald-900 flex items-center space-x-3';
            banner.innerHTML = `
                <div class="w-10 h-10 rounded-full bg-emerald-500 text-white flex items-center justify-center text-xl flex-shrink-0">
                    <i class="fa-solid fa-check"></i>
                </div>
                <div>
                    <h4 class="font-extrabold text-base">Erişim Onaylandı (ALLOW)</h4>
                    <p class="text-xs text-emerald-700">${data.reason}</p>
                </div>
            `;
        } else {
            banner.className = 'p-4 rounded-xl border border-red-300 bg-red-50 text-red-900 flex items-center space-x-3';
            banner.innerHTML = `
                <div class="w-10 h-10 rounded-full bg-red-500 text-white flex items-center justify-center text-xl flex-shrink-0">
                    <i class="fa-solid fa-xmark"></i>
                </div>
                <div>
                    <h4 class="font-extrabold text-base">Erişim Reddedildi (DENY)</h4>
                    <p class="text-xs text-red-700">${data.reason}</p>
                </div>
            `;
        }

        // Trace steps
        const traceList = document.getElementById('simTraceList');
        traceList.innerHTML = data.trace.map(t => `
            <div class="flex items-start space-x-3 text-xs p-2.5 rounded-lg border ${t.passed ? 'bg-slate-50 border-slate-200' : 'bg-red-50 border-red-200 text-red-800'}">
                <span class="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold ${t.passed ? 'bg-emerald-100 text-emerald-700' : 'bg-red-200 text-red-800'}">
                    ${t.passed ? '<i class=\"fa-solid fa-check\"></i>' : '<i class=\"fa-solid fa-xmark\"></i>'}
                </span>
                <div>
                    <strong class="font-bold block">${t.step}. ${t.name}</strong>
                    <span class="text-slate-500 text-[11px]">${t.detail}</span>
                </div>
            </div>
        `).join('');
    });
}

function jsonSafeStringify(obj) {
    return JSON.stringify(obj);
}
