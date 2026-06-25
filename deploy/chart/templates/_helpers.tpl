{{/* Chart name, overridable. */}}
{{- define "printing-erp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified release name. */}}
{{- define "printing-erp.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Chart label value (name-version). */}}
{{- define "printing-erp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every object. */}}
{{- define "printing-erp.labels" -}}
helm.sh/chart: {{ include "printing-erp.chart" . }}
{{ include "printing-erp.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Selector labels (stable across upgrades — never include version). */}}
{{- define "printing-erp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "printing-erp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Name of the Secret holding the backend's secret env vars: an operator-
     managed existing Secret, else the ExternalSecret target. */}}
{{- define "printing-erp.backendSecretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- printf "%s-backend" (include "printing-erp.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* True when a secret source (existing or external) is configured. */}}
{{- define "printing-erp.hasSecret" -}}
{{- if or .Values.existingSecret .Values.externalSecret.enabled -}}true{{- end -}}
{{- end -}}
