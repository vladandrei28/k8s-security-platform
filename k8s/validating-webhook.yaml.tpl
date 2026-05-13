apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: pod-security-webhook
webhooks:
  - name: validate.security-webhook.default.svc
    rules:
      - operations: ["CREATE"]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
    clientConfig:
      service:
        name: security-webhook
        namespace: default
        path: /validate
        port: 443
      caBundle: CA_BUNDLE_PLACEHOLDER
    admissionReviewVersions: ["v1"]
    sideEffects: None
    failurePolicy: Fail
    timeoutSeconds: 5
    namespaceSelector:
      matchLabels:
        security-policy: enforce
