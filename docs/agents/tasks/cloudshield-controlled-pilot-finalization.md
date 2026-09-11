# CloudShield Controlled Pilot Finalization Specification
# File: docs/agents/tasks/cloudshield-controlled-pilot-finalization.md
# Classification: Sole Authoritative Finalization Specification

## 1. Objective
Finalize the existing CloudShield implementation, validate it through the actual portal workflow, reconcile GitHub documentation, publish approved changes safely, and issue the final Controlled Pilot decision.

## 2. Mandatory Execution Outcomes
1. Validate and finalize Microsoft Entra authentication for Pilot.
2. Disable local authentication in Pilot mode.
3. Validate customer and service scoped RBAC.
4. Remove automatic customer-content access from administrative roles.
5. Correct temporary-access and Entra PIM terminology.
6. Close the known report evidence, provenance, privacy, PDF, CI, and DryRunMock blockers.
7. Regenerate customer reports through the actual portal endpoint.
8. Run independent negative tests.
9. Validate deployed portal behavior.
10. Reconcile README.md, SECURITY.md, CONTRIBUTING.md, architecture documents, and Mermaid diagrams with verified runtime behavior.
11. Apply approved changes to the repository.
12. Create logical commits.
13. Push the task branch safely.
14. Provide branch, commit, CI, Pull Request, and publication evidence.
15. Issue one final release decision.

## 3. Constraints
- Do not modify independent quality assertions merely to make the build pass.
- Do not mark future functionality as implemented.
- Do not set productionReady=true.
- Keep the release channel as Pilot.
- Do not push directly to main through an unsafe synchronization workflow.
- Do not create or overwrite a release tag unless every required release gate passes.
