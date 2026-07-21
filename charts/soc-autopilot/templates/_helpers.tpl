{{- define "soc-autopilot.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "soc-autopilot.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "soc-autopilot.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "soc-autopilot.labels" -}}
app.kubernetes.io/name: {{ include "soc-autopilot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "soc-autopilot.selectorLabels" -}}
app.kubernetes.io/name: {{ include "soc-autopilot.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "soc-autopilot.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "soc-autopilot.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
