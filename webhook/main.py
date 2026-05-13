from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional


app = FastAPI(title="K8s Security Webhook")


# --- Admission protocol models ---

class AdmissionRequest(BaseModel):
    uid: str
    kind: dict
    operation: str
    object: dict


class AdmissionReviewRequest(BaseModel):
    apiVersion: str
    kind: str
    request: AdmissionRequest


class AdmissionResponse(BaseModel):
    uid: str
    allowed: bool
    status: Optional[dict] = None


class AdmissionReviewResponse(BaseModel):
    apiVersion: str = "admission.k8s.io/v1"
    kind: str = "AdmissionReview"
    response: AdmissionResponse


# --- Endpoints ---

@app.get("/")
def root():
    return {"service": "k8s-security-webhook", "status": "ok"}


@app.get("/healthz")
def healthz():
    return {"status": "healthy"}


@app.post("/validate", response_model=AdmissionReviewResponse)
def validate(review: AdmissionReviewRequest):
    """
    Validates a Kubernetes admission request.
    Stub: always allow. Real policies come next.
    """
    req = review.request
    return AdmissionReviewResponse(
        response=AdmissionResponse(
            uid=req.uid,
            allowed=True,
            status={"message": "policy stub: always allow"},
        )
    )
