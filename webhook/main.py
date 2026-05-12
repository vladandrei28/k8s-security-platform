from fastapi import FastAPI

app = FastAPI(title="K8s Security Webhook")


@app.get("/")
def root():
    return {"service": "k8s-security-webhook", "status": "ok"}


@app.get("/healthz")
def healthz():
    """Liveness probe endpoint — Kubernetes will call this to check if the pod is alive."""
    return {"status": "healthy"}
