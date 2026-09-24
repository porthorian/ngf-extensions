{{- define "ngf-extensions.timedBanName" -}}
{{- default (printf "%s-ngf-timed-ban" .Release.Name) .Values.timedBan.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ngf-extensions.allowlistName" -}}
{{- default (printf "%s-allowlist" (include "ngf-extensions.timedBanName" .)) .Values.timedBan.allowlist.existingConfigMap -}}
{{- end -}}

{{- define "ngf-extensions.image" -}}
{{- if .Values.timedBan.image.digest -}}
{{- printf "%s@%s" .Values.timedBan.image.repository .Values.timedBan.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.timedBan.image.repository .Values.timedBan.image.tag -}}
{{- end -}}
{{- end -}}
