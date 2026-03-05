# Helm & Manifest Generation Security Rules

> Version: 1.0 | Last Updated: 2026-03-03

## Overview

This document defines NEVER/ALWAYS rules for generating secure Helm charts and Kubernetes manifests.

---

## Rule 1: Never Hardcode Secret Values in values.yaml

### NEVER

Include actual secret values in values.yaml or templates.

```yaml
# WRONG - values.yaml with hardcoded secrets
database:
  host: postgres.production.svc
  username: admin
  password: SuperSecret123!  # NEVER DO THIS

api:
  key: sk-1234567890abcdef  # NEVER DO THIS

oauth:
  clientId: my-client-id
  clientSecret: abcdef123456  # NEVER DO THIS
```

```yaml
# WRONG - Template with hardcoded secret
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Release.Name }}-db-secret
type: Opaque
stringData:
  password: SuperSecret123!  # NEVER commit actual values
```

### ALWAYS

Template secret references. Actual values injected at deploy time.

```yaml
# CORRECT - values.yaml with references only
database:
  host: postgres.production.svc
  username: admin
  # Password comes from:
  # 1. External Secrets Operator
  # 2. helm install --set-file
  # 3. Sealed Secrets
  existingSecretName: ""  # Use existing secret if set
  secretKey: "password"

api:
  existingSecretName: "api-credentials"
  secretKey: "api-key"
```

```yaml
# CORRECT - templates/secret.yaml (placeholder for CI/CD injection)
{{- if not .Values.database.existingSecretName }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Release.Name }}-db-secret
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-delete-policy: before-hook-creation
type: Opaque
stringData:
  # Value injected via: helm install --set database.password=xxx
  # Or via CI/CD pipeline secrets
  password: {{ required "database.password is required" .Values.database.password | quote }}
{{- end }}
```

```yaml
# CORRECT - templates/deployment.yaml referencing secrets
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        {{- if .Values.database.existingSecretName }}
        name: {{ .Values.database.existingSecretName }}
        {{- else }}
        name: {{ .Release.Name }}-db-secret
        {{- end }}
        key: {{ .Values.database.secretKey }}
```

```yaml
# CORRECT - Using External Secrets Operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: {{ .Release.Name }}-external-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: {{ .Values.externalSecrets.secretStoreName }}
    kind: ClusterSecretStore
  target:
    name: {{ .Release.Name }}-secrets
  data:
    - secretKey: db-password
      remoteRef:
        key: {{ .Values.externalSecrets.dbPasswordPath }}
    - secretKey: api-key
      remoteRef:
        key: {{ .Values.externalSecrets.apiKeyPath }}
```

---

## Rule 2: Always Include PodDisruptionBudgets for Production

### NEVER

Deploy production workloads without PodDisruptionBudgets.

```yaml
# WRONG - Deployment without PDB
# Node maintenance could take down all replicas simultaneously
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-server
spec:
  replicas: 3
  # No PDB means cluster operations can disrupt all pods
```

### ALWAYS

Include PodDisruptionBudgets for multi-replica production workloads.

```yaml
# CORRECT - values.yaml
replicaCount: 3

podDisruptionBudget:
  enabled: true
  minAvailable: 2  # or use maxUnavailable: 1
```

```yaml
# CORRECT - templates/pdb.yaml
{{- if and .Values.podDisruptionBudget.enabled (gt (int .Values.replicaCount) 1) }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "mychart.fullname" . }}
  labels:
    {{- include "mychart.labels" . | nindent 4 }}
spec:
  {{- if .Values.podDisruptionBudget.minAvailable }}
  minAvailable: {{ .Values.podDisruptionBudget.minAvailable }}
  {{- else if .Values.podDisruptionBudget.maxUnavailable }}
  maxUnavailable: {{ .Values.podDisruptionBudget.maxUnavailable }}
  {{- else }}
  minAvailable: 1
  {{- end }}
  selector:
    matchLabels:
      {{- include "mychart.selectorLabels" . | nindent 6 }}
{{- end }}
```

---

## Rule 3: Always Set Appropriate Labels and Annotations

### NEVER

Generate manifests without standard labels.

```yaml
# WRONG - Minimal labels
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels:
    app: api  # Insufficient for production
```

### ALWAYS

Include standard Kubernetes labels and relevant annotations.

```yaml
# CORRECT - templates/_helpers.tpl
{{/*
Common labels
*/}}
{{- define "mychart.labels" -}}
helm.sh/chart: {{ include "mychart.chart" . }}
{{ include "mychart.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: {{ .Values.global.applicationName | default .Chart.Name }}
app.kubernetes.io/component: {{ .Values.component | default "server" }}
{{- if .Values.commonLabels }}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mychart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mychart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Pod annotations
*/}}
{{- define "mychart.podAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
checksum/secret: {{ include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
{{- if .Values.podAnnotations }}
{{ toYaml .Values.podAnnotations }}
{{- end }}
{{- end }}
```

```yaml
# CORRECT - templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "mychart.fullname" . }}
  labels:
    {{- include "mychart.labels" . | nindent 4 }}
  annotations:
    description: {{ .Values.description | default "Managed by Helm" | quote }}
spec:
  selector:
    matchLabels:
      {{- include "mychart.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "mychart.selectorLabels" . | nindent 8 }}
      annotations:
        {{- include "mychart.podAnnotations" . | nindent 8 }}
```

---

## Rule 4: Always Include Liveness and Readiness Probes

### NEVER

Generate deployments without health check probes.

```yaml
# WRONG - No probes
spec:
  containers:
    - name: api
      image: api:v1
      # Missing probes - unhealthy containers won't restart
```

### ALWAYS

Include configurable probes with sensible defaults.

```yaml
# CORRECT - values.yaml
livenessProbe:
  enabled: true
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 15
  periodSeconds: 20
  timeoutSeconds: 5
  failureThreshold: 3
  successThreshold: 1

readinessProbe:
  enabled: true
  httpGet:
    path: /readyz
    port: http
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
  successThreshold: 1

startupProbe:
  enabled: false
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 30
```

```yaml
# CORRECT - templates/deployment.yaml
containers:
  - name: {{ .Chart.Name }}
    image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
    ports:
      - name: http
        containerPort: {{ .Values.service.targetPort }}
        protocol: TCP
    {{- if .Values.livenessProbe.enabled }}
    livenessProbe:
      {{- if .Values.livenessProbe.httpGet }}
      httpGet:
        path: {{ .Values.livenessProbe.httpGet.path }}
        port: {{ .Values.livenessProbe.httpGet.port }}
      {{- else if .Values.livenessProbe.tcpSocket }}
      tcpSocket:
        port: {{ .Values.livenessProbe.tcpSocket.port }}
      {{- else if .Values.livenessProbe.exec }}
      exec:
        command:
          {{- toYaml .Values.livenessProbe.exec.command | nindent 10 }}
      {{- end }}
      initialDelaySeconds: {{ .Values.livenessProbe.initialDelaySeconds }}
      periodSeconds: {{ .Values.livenessProbe.periodSeconds }}
      timeoutSeconds: {{ .Values.livenessProbe.timeoutSeconds }}
      failureThreshold: {{ .Values.livenessProbe.failureThreshold }}
      successThreshold: {{ .Values.livenessProbe.successThreshold }}
    {{- end }}
    {{- if .Values.readinessProbe.enabled }}
    readinessProbe:
      {{- if .Values.readinessProbe.httpGet }}
      httpGet:
        path: {{ .Values.readinessProbe.httpGet.path }}
        port: {{ .Values.readinessProbe.httpGet.port }}
      {{- else if .Values.readinessProbe.tcpSocket }}
      tcpSocket:
        port: {{ .Values.readinessProbe.tcpSocket.port }}
      {{- end }}
      initialDelaySeconds: {{ .Values.readinessProbe.initialDelaySeconds }}
      periodSeconds: {{ .Values.readinessProbe.periodSeconds }}
      timeoutSeconds: {{ .Values.readinessProbe.timeoutSeconds }}
      failureThreshold: {{ .Values.readinessProbe.failureThreshold }}
      successThreshold: {{ .Values.readinessProbe.successThreshold }}
    {{- end }}
```

---

## Rule 5: Always Include Security Context in Templates

### ALWAYS

Include comprehensive SecurityContext with secure defaults.

```yaml
# CORRECT - values.yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

```yaml
# CORRECT - templates/deployment.yaml
spec:
  template:
    spec:
      {{- with .Values.securityContext }}
      securityContext:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: {{ .Chart.Name }}
          {{- with .Values.containerSecurityContext }}
          securityContext:
            {{- toYaml . | nindent 12 }}
          {{- end }}
```

---

## Rule 6: Always Include Resource Requests and Limits

### ALWAYS

Include configurable resource specifications with sensible defaults.

```yaml
# CORRECT - values.yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

```yaml
# CORRECT - templates/deployment.yaml with validation
containers:
  - name: {{ .Chart.Name }}
    {{- if .Values.resources }}
    resources:
      {{- toYaml .Values.resources | nindent 12 }}
    {{- else }}
    {{- fail "resources must be specified" }}
    {{- end }}
```

---

## Rule 7: Always Create Dedicated ServiceAccount

### NEVER

Use the default service account.

```yaml
# WRONG - No serviceAccountName (uses default)
spec:
  template:
    spec:
      containers:
        - name: api
```

### ALWAYS

Create and use dedicated ServiceAccounts.

```yaml
# CORRECT - values.yaml
serviceAccount:
  create: true
  name: ""  # Auto-generated if empty
  annotations: {}
  automountServiceAccountToken: false
```

```yaml
# CORRECT - templates/serviceaccount.yaml
{{- if .Values.serviceAccount.create }}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "mychart.serviceAccountName" . }}
  labels:
    {{- include "mychart.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
automountServiceAccountToken: {{ .Values.serviceAccount.automountServiceAccountToken }}
{{- end }}
```

```yaml
# CORRECT - templates/deployment.yaml
spec:
  template:
    spec:
      serviceAccountName: {{ include "mychart.serviceAccountName" . }}
      automountServiceAccountToken: {{ .Values.serviceAccount.automountServiceAccountToken }}
```

---

## Complete Secure Helm Chart Structure

```
mychart/
├── Chart.yaml
├── values.yaml
├── values.schema.json          # Validate values
├── templates/
│   ├── NOTES.txt
│   ├── _helpers.tpl
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── serviceaccount.yaml
│   ├── configmap.yaml
│   ├── secret.yaml             # Template only, no values
│   ├── ingress.yaml
│   ├── networkpolicy.yaml
│   ├── pdb.yaml
│   ├── hpa.yaml                # Optional
│   └── tests/
│       └── test-connection.yaml
└── .helmignore
```

```yaml
# CORRECT - Complete values.yaml template
# Default values for mychart.

replicaCount: 2

image:
  repository: myregistry.io/myapp
  pullPolicy: IfNotPresent
  tag: ""  # Defaults to chart appVersion

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

serviceAccount:
  create: true
  annotations: {}
  name: ""
  automountServiceAccountToken: false

podAnnotations: {}

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

service:
  type: ClusterIP
  port: 80
  targetPort: 8080

ingress:
  enabled: false
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: chart-example.local
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: chart-example-tls
      hosts:
        - chart-example.local

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi

livenessProbe:
  enabled: true
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 15
  periodSeconds: 20
  timeoutSeconds: 5
  failureThreshold: 3
  successThreshold: 1

readinessProbe:
  enabled: true
  httpGet:
    path: /readyz
    port: http
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
  successThreshold: 1

networkPolicy:
  enabled: true
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx

podDisruptionBudget:
  enabled: true
  minAvailable: 1

# External secrets configuration
externalSecrets:
  enabled: false
  secretStoreName: ""
  secrets: []

# Volume mounts for writable directories
extraVolumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: cache
    mountPath: /app/cache

extraVolumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir:
      sizeLimit: 100Mi
```

---

## Pre-Commit Checklist for Helm Charts

- [ ] No hardcoded secrets in values.yaml
- [ ] Secret templates use references, not values
- [ ] PodDisruptionBudget included for production
- [ ] Standard Kubernetes labels applied
- [ ] Liveness and readiness probes configured
- [ ] SecurityContext with secure defaults
- [ ] ContainerSecurityContext with secure defaults
- [ ] Resource requests and limits defined
- [ ] Dedicated ServiceAccount created
- [ ] automountServiceAccountToken: false by default
- [ ] NetworkPolicy template included
- [ ] Ingress includes TLS configuration
- [ ] values.schema.json validates required fields
- [ ] .helmignore excludes sensitive files
