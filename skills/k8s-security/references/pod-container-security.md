# Pod & Container Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for securing Pods and containers in Kubernetes, including SecurityContext configuration, resource management, and Pod Security Standards compliance.

---

## Rule 1: Always Set SecurityContext

### NEVER

Deploy pods without explicit SecurityContext settings.

```yaml
# WRONG - No SecurityContext defined
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0
        # No securityContext - runs as root by default!
```

### ALWAYS

Set comprehensive SecurityContext at both pod and container level.

```yaml
# CORRECT - Full SecurityContext configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: api
        image: myapp:v1.0.0@sha256:abc123...
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
          # Only add specific capabilities if absolutely required:
          # capabilities:
          #   add:
          #     - NET_BIND_SERVICE  # Only if binding to ports < 1024
```

---

## Rule 2: Never Use privileged: true

### NEVER

Set `privileged: true` unless explicitly justified with a documented reason.

```yaml
# WRONG - Privileged container (full host access!)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0
        securityContext:
          privileged: true  # NEVER DO THIS without justification
```

### ALWAYS

Use non-privileged containers. If privileged access is required, document why.

```yaml
# CORRECT - Non-privileged with minimal capabilities
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0
        securityContext:
          privileged: false
          allowPrivilegeEscalation: false
          capabilities:
            drop:
              - ALL
---
# EXCEPTION - Privileged container with justification
# Only acceptable for: CNI plugins, storage drivers, node-level monitoring
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cni-plugin
  annotations:
    security.kubernetes.io/privileged-justification: |
      CNI plugin requires privileged access to configure host networking.
      Reviewed and approved by security team on 2024-01-15.
spec:
  template:
    spec:
      containers:
      - name: cni
        image: cni-plugin:v1.0.0@sha256:def456...
        securityContext:
          privileged: true  # Justified: CNI requires host network access
```

---

## Rule 3: Always Set Resource Requests AND Limits

### NEVER

Deploy containers without resource requests and limits.

```yaml
# WRONG - No resource constraints
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0
        # No resources defined - can consume unlimited resources!
```

```yaml
# WRONG - Only requests, no limits
containers:
- name: api
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    # No limits - can still consume unlimited resources
```

### ALWAYS

Set both requests AND limits for CPU and memory.

```yaml
# CORRECT - Both requests and limits defined
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0@sha256:abc123...
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        # For memory: limits >= requests
        # For CPU: limits can be higher to allow bursting
```

```yaml
# CORRECT - Production-ready resource configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0@sha256:abc123...
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
            ephemeral-storage: "100Mi"
          limits:
            memory: "512Mi"
            cpu: "1000m"
            ephemeral-storage: "500Mi"
```

---

## Rule 4: Always Set automountServiceAccountToken: false

### NEVER

Allow automatic service account token mounting unless the pod needs Kubernetes API access.

```yaml
# WRONG - Default allows token mounting
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0
        # automountServiceAccountToken defaults to true
        # Pod gets unnecessary access to K8s API
```

### ALWAYS

Explicitly disable service account token mounting unless required.

```yaml
# CORRECT - Disable token mounting for pods that don't need K8s API
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      automountServiceAccountToken: false  # Disable unless needed
      containers:
      - name: api
        image: myapp:v1.0.0@sha256:abc123...
---
# CORRECT - Enable only when K8s API access is required
apiVersion: apps/v1
kind: Deployment
metadata:
  name: controller
  annotations:
    security.kubernetes.io/sa-token-justification: |
      Controller needs to watch ConfigMaps and update Deployments.
spec:
  template:
    spec:
      serviceAccountName: controller-sa  # Dedicated SA with minimal RBAC
      automountServiceAccountToken: true  # Justified: needs K8s API access
      containers:
      - name: controller
        image: controller:v1.0.0@sha256:abc123...
```

---

## Rule 5: Always Use readOnlyRootFilesystem

### NEVER

Allow writable root filesystems unless absolutely required.

```yaml
# WRONG - Writable root filesystem (default)
containers:
- name: api
  image: myapp:v1.0.0
  securityContext:
    # readOnlyRootFilesystem defaults to false
    # Attackers can write malware to the container filesystem
```

### ALWAYS

Use read-only root filesystem with explicit writable mounts where needed.

```yaml
# CORRECT - Read-only root with specific writable paths
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0@sha256:abc123...
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir:
          sizeLimit: 100Mi
```

---

## Rule 6: Never Use ClusterRole When Role Suffices

### NEVER

Use ClusterRole for namespace-scoped operations.

```yaml
# WRONG - ClusterRole for operations that only need namespace scope
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: api-server-role
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]  # Only needs access in one namespace
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: api-server-binding
roleRef:
  kind: ClusterRole
  name: api-server-role
subjects:
- kind: ServiceAccount
  name: api-server
  namespace: production
```

### ALWAYS

Use namespace-scoped Role when possible.

```yaml
# CORRECT - Namespace-scoped Role
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-server-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-server-binding
  namespace: production
roleRef:
  kind: Role
  name: api-server-role
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: api-server
  namespace: production
```

---

## Rule 7: Always Include Liveness and Readiness Probes

### NEVER

Deploy without health check probes.

```yaml
# WRONG - No probes defined
containers:
- name: api
  image: myapp:v1.0.0
  # No livenessProbe - unhealthy containers won't restart
  # No readinessProbe - traffic sent to unready containers
```

### ALWAYS

Configure appropriate liveness and readiness probes.

```yaml
# CORRECT - Comprehensive probe configuration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  template:
    spec:
      containers:
      - name: api
        image: myapp:v1.0.0@sha256:abc123...
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 20
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        startupProbe:  # For slow-starting applications
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
          failureThreshold: 30  # 5 minutes to start
```

---

## Complete Secure Pod Template

```yaml
# CORRECT - Production-ready secure pod specification
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
  labels:
    app: api-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-server
  template:
    metadata:
      labels:
        app: api-server
      annotations:
        seccomp.security.alpha.kubernetes.io/pod: runtime/default
    spec:
      # Pod-level security
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

      # Disable SA token unless needed
      automountServiceAccountToken: false
      serviceAccountName: api-server-sa

      # Container specification
      containers:
      - name: api
        image: myregistry.io/myapp:v1.0.0@sha256:abc123def456...

        # Container-level security
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL

        # Resource constraints
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"

        # Health checks
        ports:
        - containerPort: 8080
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 20
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10

        # Environment from secrets
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-credentials
              key: api-key

        # Writable directories
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache

      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir:
          sizeLimit: 100Mi
```

---

## Pod Security Standards Compliance (Restricted Profile)

The restricted profile is the most secure. All production workloads should comply.

| Control | Restricted Requirement | Example |
|---------|----------------------|---------|
| Volumes | Only allowed types: configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret | No hostPath |
| Host Namespaces | hostNetwork, hostPID, hostIPC must be false | `hostNetwork: false` |
| Privileged | Must be false | `privileged: false` |
| Capabilities | Drop ALL, may only add NET_BIND_SERVICE | `drop: [ALL]` |
| HostPath | Not allowed | Remove hostPath volumes |
| Host Ports | Not allowed (or restricted range) | Use ClusterIP Services |
| AppArmor | Must not disable | Don't set `unconfined` |
| SELinux | Limited options | Don't set custom SELinux |
| /proc Mount | Default Masked | Use default procMount |
| Seccomp | RuntimeDefault or Localhost | `type: RuntimeDefault` |
| Sysctls | Limited safe set only | Avoid unsafe sysctls |
| Privilege Escalation | Must be false | `allowPrivilegeEscalation: false` |
| Running as Non-root | Must be true | `runAsNonRoot: true` |
| Running as Non-root User | UID must not be 0 | `runAsUser: 1000` |

---

## Pre-Commit Checklist for Pod Security

- [ ] SecurityContext defined at pod and container level
- [ ] runAsNonRoot: true
- [ ] readOnlyRootFilesystem: true
- [ ] allowPrivilegeEscalation: false
- [ ] capabilities.drop: [ALL]
- [ ] privileged: false (or justified)
- [ ] automountServiceAccountToken: false (or justified)
- [ ] Resource requests AND limits defined
- [ ] Liveness and readiness probes configured
- [ ] Image uses digest pinning (not :latest)
- [ ] seccompProfile set to RuntimeDefault
- [ ] No hostPath volumes (or justified)
- [ ] No hostNetwork/hostPID/hostIPC
