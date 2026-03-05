# RBAC & Service Accounts Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for configuring RBAC (Role-Based Access Control) and ServiceAccounts in Kubernetes following the principle of least privilege.

---

## Rule 1: Always Create Dedicated ServiceAccounts Per Workload

### NEVER

Use the default service account for application workloads.

```yaml
# WRONG - No serviceAccountName (uses default)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      # Uses default SA - shares permissions with other pods
      containers:
        - name: api
          image: api:v1.0.0
```

```yaml
# WRONG - Multiple workloads sharing one SA
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      serviceAccountName: shared-service-account  # Violates least privilege
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      serviceAccountName: shared-service-account  # Same SA, different needs
```

### ALWAYS

Create a dedicated ServiceAccount for each workload.

```yaml
# CORRECT - Dedicated ServiceAccount per workload
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api-server-sa
  namespace: production
  labels:
    app: api-server
automountServiceAccountToken: false  # Disable unless needed
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: worker-sa
  namespace: production
  labels:
    app: worker
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      serviceAccountName: api-server-sa
      automountServiceAccountToken: false  # Explicitly disable
      containers:
        - name: api
          image: api:v1.0.0@sha256:abc123...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  template:
    spec:
      serviceAccountName: worker-sa
      automountServiceAccountToken: true  # Only if worker needs K8s API
      containers:
        - name: worker
          image: worker:v1.0.0@sha256:def456...
```

---

## Rule 2: Never Use Wildcard (*) Verbs or Resources

### NEVER

Use wildcards in RBAC rules without explicit justification.

```yaml
# WRONG - Wildcard verbs (full access)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]  # NEVER - grants delete, create, etc.
```

```yaml
# WRONG - Wildcard resources (access to everything)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-role
rules:
- apiGroups: ["*"]
  resources: ["*"]  # NEVER - access to all resources
  verbs: ["get", "list"]
```

```yaml
# WRONG - Wildcard API groups
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: broad-role
rules:
- apiGroups: ["*"]  # NEVER - includes secrets, RBAC, etc.
  resources: ["configmaps"]
  verbs: ["get"]
```

### ALWAYS

Specify exact resources, verbs, and API groups.

```yaml
# CORRECT - Specific permissions only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["app-config", "feature-flags"]  # Even more specific!
```

```yaml
# CORRECT - Separate roles for separate concerns
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]  # Read logs only
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-manager
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "update", "patch"]
  # Note: no "create" or "delete" unless needed
```

---

## Rule 3: Always Use Namespace-Scoped Roles When Possible

### NEVER

Use ClusterRole/ClusterRoleBinding when namespace-scoped Role/RoleBinding suffices.

```yaml
# WRONG - ClusterRole for namespace-specific access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: api-server-role
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: api-server-binding
subjects:
- kind: ServiceAccount
  name: api-server-sa
  namespace: production
roleRef:
  kind: ClusterRole
  name: api-server-role
  # This SA can now read ALL configmaps and secrets cluster-wide!
```

### ALWAYS

Use namespace-scoped Role/RoleBinding unless cluster-wide access is truly needed.

```yaml
# CORRECT - Namespace-scoped Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-server-role
  namespace: production  # Scoped to production namespace
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
  resourceNames: ["app-config"]  # Only specific ConfigMap
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-server-binding
  namespace: production
subjects:
- kind: ServiceAccount
  name: api-server-sa
  namespace: production
roleRef:
  kind: Role
  name: api-server-role
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# CORRECT - ClusterRole with justified need and documentation
# Use case: Prometheus needs to scrape metrics from all namespaces
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-metrics-reader
  annotations:
    rbac.authorization.k8s.io/justification: |
      Prometheus requires cluster-wide access to scrape metrics endpoints.
      Reviewed and approved by security team on 2024-01-15.
rules:
- apiGroups: [""]
  resources: ["endpoints", "pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["nodes/metrics"]
  verbs: ["get"]
# Note: Still no access to secrets or RBAC
```

---

## Rule 4: Never Grant Access to Secrets Unless Required

### NEVER

Include secrets access in RBAC rules without explicit need.

```yaml
# WRONG - Unnecessary secrets access
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]  # Why secrets?
  verbs: ["get", "list", "watch"]
```

### ALWAYS

Grant secrets access only when explicitly required, with specific resource names.

```yaml
# CORRECT - No secrets access for most applications
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
# Secrets injected via env vars/volumes - no RBAC needed
```

```yaml
# CORRECT - Secrets access only when justified (e.g., cert-manager)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-manager-controller
  namespace: cert-manager
  annotations:
    rbac.authorization.k8s.io/justification: |
      cert-manager needs to create/update TLS secrets for certificates.
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "delete"]
  # Could further restrict with resourceNames for known secret patterns
```

---

## Rule 5: Use resourceNames to Restrict to Specific Resources

### ALWAYS

When possible, restrict access to specific named resources.

```yaml
# CORRECT - Access to specific ConfigMaps only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-config-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "watch"]
  resourceNames:
    - "app-config"
    - "feature-flags"
    - "rate-limits"
```

```yaml
# CORRECT - Access to specific Deployment only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-server-deployer
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "update", "patch"]
  resourceNames:
    - "api-server"
- apiGroups: ["apps"]
  resources: ["deployments/scale"]
  verbs: ["update", "patch"]
  resourceNames:
    - "api-server"
```

---

## Rule 6: Audit and Review RBAC Regularly

### ALWAYS

Include annotations documenting RBAC purpose and review schedule.

```yaml
# CORRECT - Documented RBAC with review metadata
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-manager
  namespace: production
  labels:
    app.kubernetes.io/managed-by: helm
    security.kubernetes.io/reviewed: "2024-01-15"
  annotations:
    description: |
      Allows the CI/CD service account to manage deployments
      in the production namespace.
    security.kubernetes.io/owner: platform-team
    security.kubernetes.io/review-schedule: quarterly
    security.kubernetes.io/last-reviewed: "2024-01-15"
    security.kubernetes.io/reviewer: security@example.com
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "update", "patch"]
  resourceNames:
    - "api-server"
    - "worker"
    - "scheduler"
```

---

## Common RBAC Patterns

### Pattern 1: Read-Only Application Access

```yaml
# For applications that only need to read config
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: config-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-config-reader
  namespace: production
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: Role
  name: config-reader
  apiGroup: rbac.authorization.k8s.io
```

### Pattern 2: Pod/Deployment Watcher (Controllers)

```yaml
# For controllers that need to watch and update resources
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-controller
  namespace: production
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: ["apps"]
  resources: ["deployments/status"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

### Pattern 3: CI/CD Pipeline Service Account

```yaml
# For CI/CD pipelines deploying applications
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cicd-deployer
  namespace: production
rules:
# Deployments
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
# ConfigMaps (non-sensitive config)
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
# Services
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
# Rollout status
- apiGroups: ["apps"]
  resources: ["deployments/status"]
  verbs: ["get"]
# Note: Secrets handled separately via external secrets operator
```

### Pattern 4: Cluster-Wide Monitoring (Prometheus)

```yaml
# Prometheus scraping - requires cluster-wide read access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus-scraper
  annotations:
    rbac.authorization.k8s.io/justification: |
      Prometheus needs cluster-wide read access to discover and scrape
      metrics endpoints from all namespaces.
rules:
- apiGroups: [""]
  resources:
    - nodes
    - nodes/metrics
    - services
    - endpoints
    - pods
  verbs: ["get", "list", "watch"]
- apiGroups: ["extensions", "networking.k8s.io"]
  resources:
    - ingresses
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["/metrics", "/metrics/cadvisor"]
  verbs: ["get"]
```

### Pattern 5: Namespace Admin (Team Lead)

```yaml
# Team lead with full access to team namespace only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: namespace-admin
  namespace: team-a
rules:
- apiGroups: ["", "apps", "batch", "extensions", "networking.k8s.io"]
  resources: ["*"]
  verbs: ["*"]
# Explicitly exclude cluster-level resources and dangerous operations
# This is a Role, so it can't affect other namespaces
---
# Additional ClusterRole for viewing cluster resources (read-only)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-viewer
rules:
- apiGroups: [""]
  resources: ["namespaces", "nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses"]
  verbs: ["get", "list", "watch"]
```

---

## Pre-Commit Checklist for RBAC

- [ ] Each workload has dedicated ServiceAccount
- [ ] automountServiceAccountToken: false unless K8s API access needed
- [ ] No wildcard (*) verbs without documented justification
- [ ] No wildcard (*) resources without documented justification
- [ ] No wildcard (*) apiGroups without documented justification
- [ ] Role used instead of ClusterRole where possible
- [ ] Secrets access only when explicitly required
- [ ] resourceNames used to restrict to specific resources where possible
- [ ] RBAC includes documentation annotations
- [ ] RBAC reviewed and approved by security team
- [ ] No default service account used by application pods
- [ ] ClusterRoleBindings documented with justification
