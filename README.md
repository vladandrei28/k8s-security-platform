# Kubernetes Cloud-Native Security Platform

A Kubernetes admission controller and runtime security platform combining policy enforcement, image vulnerability scanning, threat intelligence-based blacklisting, and SIEM forwarding to Azure Sentinel.

> 🚧 Work in progress — built as a hands-on study in cloud-native security.

## Goals

- Block pods with vulnerable container images before they're scheduled
- Enforce baseline pod security (no root, no privileged, no host networking)
- Dynamically refresh image blacklists from threat intel feeds (MISP, AbuseIPDB, OTX)
- Detect suspicious runtime behavior with Falco
- Forward security events to Azure Sentinel with KQL detection rules

## Tech stack

Python 3.11, FastAPI, kubernetes-client, Trivy, Falco, Redis, Azure Sentinel, k3d (local dev).

## License

MIT
