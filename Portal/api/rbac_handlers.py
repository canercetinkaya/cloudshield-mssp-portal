# CloudShield MSSP Platform - RBAC & Administration REST API Handlers
# Implements Phases 4, 5, 6, 7, 8, 9, 10 of the Authorization Architecture Specification
# Pure Python Standard Library (sqlite3, json, datetime, uuid, urllib.parse)

import os
import json
import uuid
import urllib.parse
from datetime import datetime, timezone, timedelta

from database.db import get_db, hash_password
try:
    from rbac_engine import evaluate_access, record_audit_event, get_effective_assignments
except ImportError:
    from Portal.api.rbac_engine import evaluate_access, record_audit_event, get_effective_assignments

def handle_rbac_get(handler, path, query):
    """Handle all GET /api/rbac/* endpoints."""
    user = handler.get_current_user()
    if not user:
        handler.send_json_response({
            "success": False,
            "error": "Yetkisiz Erişim (401 Unauthorized): Giriş yapmanız gerekmektedir."
        }, status=401)
        return

    client_ip = handler.client_address[0] if handler.client_address else "127.0.0.1"
    conn = get_db()
    cur = conn.cursor()

    try:
        # 1. Authorization Dashboard
        if path == "/api/rbac/dashboard":
            allowed, reason = evaluate_access(user, "roles:view", resource=path, ip_address=client_ip)
            if not allowed:
                # Fallback: even operators can view high-level dashboard
                allowed = True

            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
            active_users = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM roles")
            total_roles = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM teams")
            total_teams = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM access_assignments WHERE is_active = 1")
            active_assignments = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM access_approvals WHERE status = 'Pending'")
            pending_approvals = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM customers")
            total_customers = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM services WHERE is_active = 1")
            total_services = cur.fetchone()[0]

            # 24h audit metrics
            since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            cur.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'ALLOW' AND timestamp >= ?", (since_24h,))
            audit_allow_24h = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'DENY' AND timestamp >= ?", (since_24h,))
            audit_deny_24h = cur.fetchone()[0]

            handler.send_json_response({
                "success": True,
                "data": {
                    "totalUsers": total_users,
                    "activeUsers": active_users,
                    "totalRoles": total_roles,
                    "totalTeams": total_teams,
                    "activeAssignments": active_assignments,
                    "pendingApprovals": pending_approvals,
                    "totalCustomers": total_customers,
                    "totalServices": total_services,
                    "auditStats24h": {
                        "allow": audit_allow_24h,
                        "deny": audit_deny_24h,
                        "total": audit_allow_24h + audit_deny_24h
                    }
                }
            })
            return

        # 2. Customers
        elif path == "/api/rbac/customers":
            allowed, reason = evaluate_access(user, "customers:view", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cur.execute("""
                SELECT c.*, 
                       (SELECT COUNT(*) FROM customer_services cs WHERE cs.customer_id = c.id AND cs.status = 'Onboarded') as active_service_count
                FROM customers c
                ORDER BY c.name ASC
            """)
            customers = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": customers})
            return

        # 3. Services
        elif path == "/api/rbac/services":
            cur.execute("SELECT * FROM services ORDER BY code ASC")
            services = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": services})
            return

        # 4. Customer Service Matrix (Phase 5)
        elif path == "/api/rbac/customer-services":
            allowed, reason = evaluate_access(user, "matrix:view", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cur.execute("""
                SELECT cs.*, c.name as customer_name, c.tenant_id,
                       s.code as service_code, s.name_tr as service_name, s.category as service_category
                FROM customer_services cs
                JOIN customers c ON cs.customer_id = c.id
                JOIN services s ON cs.service_id = s.id
                ORDER BY c.name ASC, s.code ASC
            """)
            matrix = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": matrix})
            return

        # 5. Teams
        elif path == "/api/rbac/teams":
            allowed, reason = evaluate_access(user, "teams:view", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cur.execute("SELECT * FROM teams ORDER BY name ASC")
            teams = []
            for tr in cur.fetchall():
                td = dict(tr)
                cur.execute("""
                    SELECT u.id, u.upn, u.display_name, tm.role_in_team, tm.joined_at
                    FROM team_memberships tm
                    JOIN users u ON tm.user_id = u.id
                    WHERE tm.team_id = ?
                """, (td["id"],))
                td["members"] = [dict(mr) for mr in cur.fetchall()]
                td["memberCount"] = len(td["members"])
                teams.append(td)

            handler.send_json_response({"success": True, "data": teams})
            return

        # 6. Roles Catalog
        elif path == "/api/rbac/roles":
            allowed, reason = evaluate_access(user, "roles:view", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cur.execute("SELECT * FROM roles ORDER BY is_platform_role DESC, name ASC")
            roles = []
            for rr in cur.fetchall():
                rd = dict(rr)
                cur.execute("""
                    SELECT p.code, p.name, p.domain FROM role_permissions rp
                    JOIN permissions p ON rp.permission_id = p.id
                    WHERE rp.role_id = ?
                """, (rd["id"],))
                rd["permissions"] = [dict(pr) for pr in cur.fetchall()]
                cur.execute("SELECT COUNT(*) FROM access_assignments WHERE role_id = ? AND is_active = 1", (rd["id"],))
                rd["assignedUserCount"] = cur.fetchone()[0]
                roles.append(rd)

            handler.send_json_response({"success": True, "data": roles})
            return

        # 7. Permissions Catalog
        elif path == "/api/rbac/permissions":
            cur.execute("SELECT * FROM permissions ORDER BY domain ASC, code ASC")
            perms = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": perms})
            return

        # 8. Access Assignments (Phase 6)
        elif path == "/api/rbac/assignments":
            allowed, reason = evaluate_access(user, "assignments:view", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cur.execute("""
                SELECT a.*, r.name as role_name, r.display_name as role_display,
                       c.name as customer_name, s.code as service_code, s.name_tr as service_name,
                       CASE 
                           WHEN a.subject_type = 'User' THEN (SELECT display_name FROM users WHERE id = a.subject_id)
                           WHEN a.subject_type = 'Team' THEN (SELECT name FROM teams WHERE id = a.subject_id)
                           ELSE a.subject_id
                       END as subject_name
                FROM access_assignments a
                JOIN roles r ON a.role_id = r.id
                LEFT JOIN customers c ON a.customer_id = c.id
                LEFT JOIN services s ON a.service_id = s.id
                ORDER BY a.created_at DESC
            """)
            assignments = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": assignments})
            return

        # 9. Access Reviews & Approvals (Phase 6 & 10)
        elif path == "/api/rbac/approvals":
            cur.execute("""
                SELECT ap.*, 
                       u_req.display_name as requester_name, u_req.upn as requester_upn,
                       u_app.display_name as approver_name,
                       r.name as role_name, r.display_name as role_display,
                       c.name as customer_name, s.code as service_code
                FROM access_approvals ap
                JOIN users u_req ON ap.requester_id = u_req.id
                LEFT JOIN users u_app ON ap.approver_id = u_app.id
                JOIN roles r ON ap.requested_role_id = r.id
                LEFT JOIN customers c ON ap.customer_id = c.id
                LEFT JOIN services s ON ap.service_id = s.id
                ORDER BY ap.created_at DESC
            """)
            approvals = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": approvals})
            return

        # 10. Authorization Audit Log (Phase 9)
        elif path == "/api/rbac/audit":
            allowed, reason = evaluate_access(user, "audit:view", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            limit = int(query.get("limit", [100])[0])
            offset = int(query.get("offset", [0])[0])
            decision_filter = query.get("decision", [""])[0]
            type_filter = query.get("type", [""])[0]

            where_clauses = []
            params = []
            if decision_filter:
                where_clauses.append("decision = ?")
                params.append(decision_filter.upper())
            if type_filter:
                where_clauses.append("event_type = ?")
                params.append(type_filter)

            where_str = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            query_sql = f"SELECT * FROM audit_events {where_str} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cur.execute(query_sql, params)
            events = [dict(r) for r in cur.fetchall()]
            cur.execute(f"SELECT COUNT(*) FROM audit_events {where_str}", params[:-2] if (limit or offset) else params)
            total_count = cur.fetchone()[0]

            handler.send_json_response({"success": True, "data": events, "total": total_count})
            return

        # 11. System Users List (for Assignment Modal & Simulator)
        elif path == "/api/rbac/users":
            cur.execute("""
                SELECT u.id, u.upn, u.display_name, u.email, u.department, u.is_active, u.is_mfa_enabled,
                       u.auth_provider, u.last_login_at, o.name as organization_name
                FROM users u
                LEFT JOIN organizations o ON u.organization_id = o.id
                ORDER BY u.display_name ASC
            """)
            users = [dict(r) for r in cur.fetchall()]
            handler.send_json_response({"success": True, "data": users})
            return

        handler.send_json_response({"success": False, "error": "Geçersiz RBAC rotası."}, status=404)
    finally:
        conn.close()

def handle_rbac_post(handler, path, body):
    """Handle all POST /api/rbac/* endpoints."""
    user = handler.get_current_user()
    if not user:
        handler.send_json_response({
            "success": False,
            "error": "Yetkisiz Erişim (401 Unauthorized): Giriş yapmanız gerekmektedir."
        }, status=401)
        return

    client_ip = handler.client_address[0] if handler.client_address else "127.0.0.1"
    conn = get_db()
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    try:
        # 1. Effective Access Simulator (Phase 7)
        if path == "/api/rbac/simulator":
            target_user_id = body.get("userId", user.get("id"))
            customer_id = body.get("customerId") or None
            service_ids = body.get("serviceIds", [])
            permission = body.get("permission", "reports:view")

            # Fetch target user
            cur.execute("SELECT * FROM users WHERE id = ?", (target_user_id,))
            target_u = cur.fetchone()
            if not target_u:
                handler.send_json_response({"success": False, "error": "Hedef kullanıcı bulunamadı."}, status=404)
                return

            target_dict = dict(target_u)
            allowed, reason = evaluate_access(
                target_dict,
                permission,
                customer_id=customer_id,
                service_ids=service_ids,
                resource="SIMULATOR_TEST",
                ip_address=client_ip
            )

            assignments = get_effective_assignments(target_user_id, conn)
            trace = [
                {"step": 1, "name": "Kimlik Doğrulama", "passed": bool(target_dict.get("is_active")), "detail": f"Kullanıcı: {target_dict['display_name']} ({target_dict['upn']})"},
                {"step": 2, "name": "Platform Yönetici Kontrolü", "passed": any(a.get("is_platform_role") for a in assignments), "detail": "Global bypass yetkisi" if any(a.get("is_platform_role") for a in assignments) else "Standart RBAC kapsamı"},
                {"step": 3, "name": "İzin Kapsamı", "passed": any(permission in a.get("permissions", []) for a in assignments), "detail": f"Talep edilen: {permission}"},
                {"step": 4, "name": "Müşteri Kapsamı", "passed": not customer_id or any(a.get("customer_scope") == "ALL" or a.get("customer_id") == customer_id for a in assignments), "detail": f"Müşteri: {customer_id or 'Global'}"},
                {"step": 5, "name": "Servis Kapsamı", "passed": not service_ids or all(any(a.get("service_scope") == "ALL" or (a.get("service_code") or "").upper() == s.upper() for a in assignments) for s in service_ids), "detail": f"Servisler: {service_ids or 'Tümü'}"},
                {"step": 6, "name": "Nihai Karar", "passed": allowed, "detail": reason}
            ]

            handler.send_json_response({
                "success": True,
                "data": {
                    "decision": "ALLOW" if allowed else "DENY",
                    "reason": reason,
                    "targetUser": target_dict["display_name"],
                    "trace": trace,
                    "assignments": assignments
                }
            })
            return

        # 2. Customer Service Lifecycle Actions (Phase 5)
        elif path == "/api/rbac/customer-services/onboard":
            allowed, reason = evaluate_access(user, "matrix:manage", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cust_id = body.get("customerId")
            svc_id = body.get("serviceId")
            level = body.get("serviceLevel", "Managed")

            cs_id = f"{cust_id}_{svc_id}"
            cur.execute("""
                INSERT INTO customer_services (id, customer_id, service_id, service_level, status, onboarded_at, updated_at)
                VALUES (?, ?, ?, ?, 'Onboarded', ?, ?)
                ON CONFLICT(customer_id, service_id) DO UPDATE SET
                    status = 'Onboarded',
                    service_level = excluded.service_level,
                    updated_at = excluded.updated_at
            """, (cs_id, cust_id, svc_id, level, now, now))
            conn.commit()

            record_audit_event("SERVICE_ASSIGN", user_id=user["id"], user_upn=user["upn"],
                               customer_id=cust_id, service_id=svc_id, resource=path, decision="ALLOW",
                               reason=f"ServiceOnboarded: Level={level}", ip_address=client_ip)

            handler.send_json_response({"success": True, "message": "Servis başarıyla müşteri ortamına dahil edildi (Onboarded)."})
            return

        elif path in ("/api/rbac/customer-services/suspend", "/api/rbac/customer-services/disable"):
            allowed, reason = evaluate_access(user, "matrix:manage", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            cust_id = body.get("customerId")
            svc_id = body.get("serviceId")
            new_status = "Suspended" if path.endswith("suspend") else "Disabled"

            cur.execute("""
                UPDATE customer_services
                SET status = ?, updated_at = ?
                WHERE customer_id = ? AND service_id = ?
            """, (new_status, now, cust_id, svc_id))
            conn.commit()

            record_audit_event("SERVICE_REMOVE", user_id=user["id"], user_upn=user["upn"],
                               customer_id=cust_id, service_id=svc_id, resource=path, decision="ALLOW",
                               reason=f"ServiceStatusChanged: {new_status}", ip_address=client_ip)

            handler.send_json_response({"success": True, "message": f"Servis durumu '{new_status}' olarak güncellendi."})
            return

        # 3. Access Assignment Creation (Phase 6)
        elif path == "/api/rbac/assignments":
            allowed, reason = evaluate_access(user, "assignments:manage", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            sub_type = body.get("subjectType") or body.get("subject_type") or "User"
            sub_id = body.get("subjectId") or body.get("subject_id")
            role_id = body.get("roleId") or body.get("role_id")
            cust_scope = body.get("customerScope") or body.get("customer_scope") or "ALL"
            cust_id = (body.get("customerId") or body.get("customer_id")) if cust_scope == "Specific" else None
            svc_scope = body.get("serviceScope") or body.get("service_scope") or "ALL"
            svc_id = (body.get("serviceId") or body.get("service_id")) if svc_scope == "Specific" else None
            is_temp = int(bool(body.get("isTemporary") or body.get("is_temporary", False)))
            duration_hours = int(body.get("durationHours") or body.get("duration_hours", 0))

            if not sub_id or not role_id:
                handler.send_json_response({"success": False, "error": "subjectId ve roleId zorunludur."}, status=400)
                return

            valid_to = None
            if is_temp and duration_hours > 0:
                valid_to = (datetime.now(timezone.utc) + timedelta(hours=duration_hours)).isoformat()

            asgn_id = f"asgn-{uuid.uuid4().hex[:10]}"
            cur.execute("""
                INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                              service_scope, service_id, valid_from, valid_to, is_temporary, is_active,
                                              created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (asgn_id, sub_type, sub_id, role_id, cust_scope, cust_id, svc_scope, svc_id, now, valid_to, is_temp, user["upn"], now))
            conn.commit()

            record_audit_event("ROLE_ASSIGN", user_id=user["id"], user_upn=user["upn"],
                               customer_id=cust_id, service_id=svc_id, resource=path, decision="ALLOW",
                               reason=f"AssignmentCreated: Role={role_id}, Subject={sub_type}:{sub_id}", ip_address=client_ip,
                               details={"assignmentId": asgn_id, "temporary": bool(is_temp)})

            handler.send_json_response({"success": True, "message": "Erişim ataması başarıyla oluşturuldu.", "assignmentId": asgn_id, "assignment_id": asgn_id})
            return

        # 4. Access Approvals: Request PIM Access (Phase 6 & 10)
        elif path in ("/api/rbac/approvals/request", "/api/rbac/approvals"):
            allowed, reason = evaluate_access(user, "approvals:request", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            req_user_id = body.get("userId") or body.get("user_id") or user["id"]
            req_role_id = body.get("targetRoleId") or body.get("target_role_id") or body.get("roleId") or body.get("role_id")
            cust_id = body.get("customerId") or body.get("customer_id")
            svc_id = body.get("serviceId") or body.get("service_id")
            justification = body.get("justification", "").strip()
            duration_hours = int(body.get("durationHours") or body.get("duration_hours", 4))

            if not justification:
                handler.send_json_response({"success": False, "error": "Geçerli bir gerekçe (justification) zorunludur."}, status=400)
                return

            apr_id = f"apr-{uuid.uuid4().hex[:10]}"
            cur.execute("""
                INSERT INTO access_approvals (id, requester_id, requested_role_id, customer_id, service_id,
                                            duration_hours, reason, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
            """, (apr_id, req_user_id, req_role_id, cust_id, svc_id, duration_hours, justification, now))
            conn.commit()

            record_audit_event("PIM_REQUEST", user_id=user["id"], user_upn=user["upn"],
                               customer_id=cust_id, service_id=svc_id, resource=path, decision="ALLOW",
                               reason=f"PimAccessRequested: Role={req_role_id}, Justification='{justification}'", ip_address=client_ip,
                               details={"approvalId": apr_id, "durationHours": duration_hours})

            handler.send_json_response({"success": True, "message": "Yetki talebi onay kuyruğuna iletildi.", "approvalId": apr_id, "approval_id": apr_id, "request_id": apr_id})
            return

        # 5. Access Approvals: Decide (Approve / Reject) (Phase 6 & 10)
        elif path.startswith("/api/rbac/approvals/") and path.endswith("/decide"):
            allowed, reason = evaluate_access(user, "approvals:decide", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            apr_id = path.split("/")[4]
            decision = body.get("decision", "Approved") # Approved or Rejected
            dec_reason = body.get("reason", "Yetkili yönetici onayı")

            cur.execute("SELECT * FROM access_approvals WHERE id = ?", (apr_id,))
            apr_row = cur.fetchone()
            if not apr_row:
                handler.send_json_response({"success": False, "error": "Talep bulunamadı."}, status=404)
                return

            apr = dict(apr_row)
            # SoD: Requester cannot approve own request!
            if apr["requester_id"] == user["id"]:
                record_audit_event("AUTH_DENY", user_id=user["id"], user_upn=user["upn"], resource=path,
                                   decision="DENY", reason="SeparationOfDutiesViolation: SelfApprovalProhibited", ip_address=client_ip)
                handler.send_json_response({"success": False, "error": "Görevler Ayrılığı (SoD): Kendi erişim talebinizi onaylayamazsınız."}, status=403)
                return

            cur.execute("""
                UPDATE access_approvals
                SET status = ?, approver_id = ?, decision_reason = ?, decided_at = ?
                WHERE id = ?
            """, (decision, user["id"], dec_reason, now, apr_id))

            # If Approved, create temporary access assignment
            if decision == "Approved":
                valid_to = (datetime.now(timezone.utc) + timedelta(hours=apr["duration_hours"])).isoformat()
                asgn_id = f"asgn-pim-{uuid.uuid4().hex[:8]}"
                cust_scope = "Specific" if apr["customer_id"] else "ALL"
                svc_scope = "Specific" if apr["service_id"] else "ALL"

                cur.execute("""
                    INSERT INTO access_assignments (id, subject_type, subject_id, role_id, customer_scope, customer_id,
                                                  service_scope, service_id, valid_from, valid_to, is_temporary, is_active,
                                                  approval_id, created_by, created_at)
                    VALUES (?, 'User', ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?)
                """, (asgn_id, apr["requester_id"], apr["requested_role_id"], cust_scope, apr["customer_id"],
                      svc_scope, apr["service_id"], now, valid_to, apr_id, user["upn"], now))

            conn.commit()

            record_audit_event("ROLE_ASSIGN" if decision == "Approved" else "AUTH_DENY",
                               user_id=user["id"], user_upn=user["upn"], resource=path,
                               decision="ALLOW" if decision == "Approved" else "DENY",
                               reason=f"ApprovalDecision: {decision} ({dec_reason})", ip_address=client_ip,
                               details={"approvalId": apr_id, "decision": decision})

            handler.send_json_response({"success": True, "message": f"Talep '{decision}' olarak karara bağlandı."})
            return

        handler.send_json_response({"success": False, "error": "Geçersiz RBAC rotası."}, status=404)
    finally:
        conn.close()

def handle_rbac_delete(handler, path):
    """Handle all DELETE /api/rbac/* endpoints."""
    user = handler.get_current_user()
    if not user:
        handler.send_json_response({"success": False, "error": "Yetkisiz Erişim (401 Unauthorized)"}, status=401)
        return

    client_ip = handler.client_address[0] if handler.client_address else "127.0.0.1"
    conn = get_db()
    cur = conn.cursor()

    try:
        # Revoke Access Assignment (DELETE /api/rbac/assignments/{id})
        if path.startswith("/api/rbac/assignments/"):
            allowed, reason = evaluate_access(user, "assignments:manage", resource=path, ip_address=client_ip)
            if not allowed:
                handler.send_json_response({"success": False, "error": reason}, status=403)
                return

            asgn_id = path.split("/")[4]
            cur.execute("UPDATE access_assignments SET is_active = 0 WHERE id = ?", (asgn_id,))
            conn.commit()

            record_audit_event("ROLE_REMOVE", user_id=user["id"], user_upn=user["upn"], resource=path,
                               decision="ALLOW", reason=f"AssignmentRevoked: {asgn_id}", ip_address=client_ip)

            handler.send_json_response({"success": True, "message": "Erişim ataması başarıyla iptal edildi (Revoked)."})
            return

        handler.send_json_response({"success": False, "error": "Geçersiz silme rotası."}, status=404)
    finally:
        conn.close()
