# AegisScan Kubernetes / Horizontal Scaling

The manifests in this directory are deployment contracts, not fake local infrastructure. They intentionally do not bundle PostgreSQL or Redis; production should use managed/external instances and inject real connection strings through Secrets.

## Components

- `aegisscan-api`: stateless FastAPI replicas, readiness/liveness probes, rolling update, PDB, CPU/memory HPA (2-10 replicas).
- `aegisscan-worker`: Celery workers, independently scalable (2-12 replicas).
- `aegisscan-beat`: single Celery Beat instance; do not horizontally scale Beat.

## Prerequisites

- Kubernetes metrics-server for resource HPA.
- A real container image for the backend, replacing `CHANGE_ME`.
- PostgreSQL and Redis reachable from the cluster.
- Kubernetes Secret values supplied out-of-band (Sealed Secrets, External Secrets, or your platform secret manager).

## Apply

```bash
kubectl apply -f namespace.yaml
kubectl apply -n aegisscan -f config.example.yaml
kubectl apply -f aegisscan.yaml
kubectl -n aegisscan get deploy,pods,hpa,pdb
```

`config.example.yaml` is intentionally an example. Never commit production credentials.

## Scaling model

API and worker pools scale independently. API scale protects request latency; worker scale protects asynchronous validation throughput. Scale-down is intentionally conservative to avoid thrashing. For queue-depth based worker autoscaling, install KEDA and add a Redis/Celery queue metric trigger rather than pretending CPU is a queue signal.
