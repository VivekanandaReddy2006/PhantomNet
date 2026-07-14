# Ollama Docker Installation & Developer Bootstrap Guide

> **PhantomNet Sentinel Layer — Local LLM Infrastructure**
> Revision: 2.0 | Last Updated: 2026-07-14 | Author: PhantomNet AI/ML Team

This document provides the complete, production-ready procedures for provisioning, configuring, benchmarking, and troubleshooting the **Dockerized Ollama inference daemon** integrated into the PhantomNet Sentinel Layer. It covers GPU pass-through on both native Linux and Windows (WSL2/Docker Desktop) hosts.

---

## Table of Contents

1. [System Pre-requisites](#1-system-pre-requisites)
2. [NVIDIA Container Toolkit Installation](#2-nvidia-container-toolkit-installation)
3. [Docker Compose Configuration](#3-docker-compose-configuration)
4. [Container Lifecycle Management](#4-container-lifecycle-management)
5. [Pulling Target Models](#5-pulling-target-models)
6. [REST API Verification](#6-rest-api-verification)
7. [Benchmark Methodology & Results](#7-benchmark-methodology--results)
8. [Environment Variable Reference](#8-environment-variable-reference)
9. [CPU-Only Fallback Mode](#9-cpu-only-fallback-mode)
10. [Troubleshooting](#10-troubleshooting)
11. [Security Considerations](#11-security-considerations)

---

## 1. System Pre-requisites

### Hardware Requirements

| Component | Minimum (CPU-only) | Recommended (GPU) |
|:---|:---|:---|
| **CPU** | 4-core x86_64 | 8-core AMD Ryzen 7 / Intel i7 |
| **RAM** | 8 GB | 16 GB+ |
| **VRAM** | — | 6 GB+ (NVIDIA CUDA) |
| **Disk** | 10 GB free | 25 GB+ SSD (model weights ~4.1 GB per model) |
| **OS** | Ubuntu 22.04+ / Windows 10+ (WSL2) | Ubuntu 22.04 LTS / Windows 11 (WSL2) |

### Software Dependencies

| Dependency | Version | Purpose |
|:---|:---|:---|
| **Docker Engine** | ≥ 24.0 | Container runtime |
| **Docker Compose** | ≥ 2.20 (V2 plugin) | Multi-service orchestration |
| **NVIDIA Driver** | ≥ 535.x | GPU kernel communication |
| **NVIDIA Container Toolkit** | ≥ 1.14 | Docker ↔ GPU bridge |
| **Docker Desktop** (Windows) | ≥ 4.25 | WSL2 backend with GPU |

### Pre-flight Checks

```powershell
# Verify Docker is running
docker --version
docker compose version

# Verify NVIDIA driver (host or WSL2)
nvidia-smi

# Verify NVIDIA Container Toolkit integration
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```

> **Windows/WSL2 Note:** You do **not** install NVIDIA drivers inside WSL2. The NVIDIA Container Toolkit forwards GPU calls from the container through WSL2 to the host Windows driver automatically. Ensure "Use the WSL 2 based engine" is enabled in Docker Desktop → Settings → General.

---

## 2. NVIDIA Container Toolkit Installation

### Linux (Ubuntu/Debian)

```bash
# 1. Add the NVIDIA container toolkit GPG key and repo
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

# 2. Install the toolkit
sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit

# 3. Configure Docker runtime and restart
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

### Windows (Docker Desktop + WSL2)

1. Install the latest [NVIDIA GeForce Game Ready or Studio Driver](https://www.nvidia.com/Download/index.aspx) on **Windows** (not inside WSL2).
2. Open **Docker Desktop** → **Settings** → **General** → Enable **"Use the WSL 2 based engine"**.
3. In **Docker Desktop** → **Settings** → **Resources** → **WSL Integration**, enable your preferred WSL2 distro.
4. Docker Desktop automatically exposes the GPU to containers via the Windows NVIDIA driver — no toolkit install required inside WSL2.

### Verification

```bash
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```

Expected output should show your GPU model, driver version, and CUDA version. If this fails, the Ollama container will fall back to **CPU-only mode**.

---

## 3. Docker Compose Configuration

The Ollama daemon is provisioned as a dedicated service in the primary `docker-compose.yml`:

```yaml
services:
  # ... (existing PhantomNet services: postgres, ssh_honeypot, api, etc.)

  ollama:
    image: ollama/ollama:latest
    container_name: phantomnet_ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - app_net
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:11434/ || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s

volumes:
  postgres_data:
  ollama_data:     # Persists downloaded model weights across restarts
```

### Configuration Breakdown

| Directive | Purpose |
|:---|:---|
| `image: ollama/ollama:latest` | Official Ollama container with `llama.cpp` backend |
| `ports: "11434:11434"` | Exposes REST API to host for dev tooling & external verification |
| `volumes: ollama_data:/root/.ollama` | **Critical** — persists model weights (~4.1 GB for Mistral) across container restarts |
| `deploy.resources.reservations.devices` | Requests NVIDIA GPU access via the Container Toolkit |
| `count: all` | Allocates all available GPUs. Use `count: 1` for multi-GPU hosts to limit to one GPU |
| `capabilities: [gpu]` | Declares CUDA compute capability requirement |
| `networks: app_net` | Shares the internal Docker network with the API service for `http://ollama:11434` resolution |

### Network Topology

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network: app_net               │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │ phantomnet_api│───▶│phantomnet_   │    │ phantomnet_ │ │
│  │   :8000       │    │  ollama:11434│    │ postgres   │ │
│  └──────────────┘    └──────────────┘    └────────────┘ │
│         │                     ▲                          │
│         │    HTTP POST        │                          │
│         │ /api/generate       │                          │
│         └─────────────────────┘                          │
│                                                          │
│  Internal URL: http://ollama:11434                       │
│  External URL: http://localhost:11434                    │
└─────────────────────────────────────────────────────────┘
```

---

## 4. Container Lifecycle Management

### First-Time Setup (Full Stack)

```powershell
# Clone and enter project
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet

# Copy environment template
cp .env.example .env

# Edit .env — enable LLM integration
# Set SENTINEL_LLM_ENABLED=true
# Set SENTINEL_LLM_HOST=http://ollama:11434
# Set SENTINEL_LLM_MODEL=mistral

# Start the full stack (builds + pulls images)
docker compose up -d

# Verify Ollama is healthy
docker compose ps
docker logs phantomnet_ollama
```

### Starting / Stopping Individual Services

```powershell
# Start only Ollama (and its dependencies)
docker compose up -d ollama

# Stop Ollama without removing the volume (models preserved)
docker compose stop ollama

# Restart with fresh container (models preserved via volume)
docker compose restart ollama

# Full teardown (WARNING: removes volumes — re-download required)
docker compose down -v
```

### Updating Ollama

```powershell
# Pull latest Ollama image
docker compose pull ollama

# Recreate container with new image (models in volume are preserved)
docker compose up -d ollama
```

---

## 5. Pulling Target Models

Once the container is running, pull model weights into the persistent volume.

### Primary Model: Mistral 7B

```powershell
docker exec -it phantomnet_ollama ollama pull mistral
```

**Model Details:**
- **Parameters:** 7.3B (Mistral-7B-Instruct-v0.3)
- **Quantization:** Q4_K_M (4-bit, medium quality)
- **Download Size:** ~4.1 GB
- **Context Window:** 32,768 tokens
- **License:** Apache 2.0
- **Capabilities:** Text generation, instruction following, function calling (v0.3)

### Resource-Constrained Fallback Models

For development systems with < 8 GB VRAM or running entirely on CPU:

| Model | Parameters | Size | VRAM Needed | Pull Command |
|:---|:---|:---|:---|:---|
| **Mistral 7B** (primary) | 7.3B | 4.1 GB | ~4.8 GB | `docker exec -it phantomnet_ollama ollama pull mistral` |
| **Phi-3 Mini** (fallback) | 3.8B | 2.2 GB | ~2.9 GB | `docker exec -it phantomnet_ollama ollama pull phi3:3.8b` |
| **Gemma 2B** (minimal) | 2B | 1.4 GB | ~2.1 GB | `docker exec -it phantomnet_ollama ollama pull gemma:2b` |

### Verifying Pulled Models

```powershell
docker exec -it phantomnet_ollama ollama list
```

Expected output:
```
NAME               ID              SIZE     MODIFIED
mistral:latest     f974a74358d6    4.1 GB   2 minutes ago
phi3:3.8b          a2c89ceaed85    2.2 GB   1 minute ago
gemma:2b           b50d6c999e59    1.4 GB   30 seconds ago
```

---

## 6. REST API Verification

### Basic Health Check

```powershell
# Check if Ollama is responding
curl http://localhost:11434/

# Expected: "Ollama is running"
```

### Test Inference (Non-streaming)

```powershell
curl -X POST http://localhost:11434/api/generate -d '{
  "model": "mistral",
  "prompt": "Explain what a honeypot healthcheck filter does in 1 sentence.",
  "stream": false
}'
```

### Test Chat Completion

```powershell
curl -X POST http://localhost:11434/api/chat -d '{
  "model": "mistral",
  "messages": [
    {"role": "user", "content": "What is a honeypot in cybersecurity?"}
  ],
  "stream": false
}'
```

### Verify GPU Detection (Container Logs)

```powershell
docker logs phantomnet_ollama 2>&1 | Select-String -Pattern "gpu|cuda|nvidia"
```

Look for lines indicating GPU detection:
```
msg="detected gpu" library=cuda compute=8.9 driver=12.4 name="NVIDIA GeForce RTX 4070" ...
```

If GPU is **not** detected, you will see:
```
msg="no nvidia gpu detected" ...
```

---

## 7. Benchmark Methodology & Results

### Benchmark Methodology

All benchmarks use the Ollama REST API with `"stream": false` to capture precise timing metrics returned in the response JSON:

| Metric | JSON Field | Unit | Description |
|:---|:---|:---|:---|
| **Load Duration** | `load_duration` | nanoseconds | Time to load model weights into memory (cold start) |
| **Prompt Eval Duration** | `prompt_eval_duration` | nanoseconds | Time to process the input prompt (prefill) |
| **Eval Duration** | `eval_duration` | nanoseconds | Time spent generating output tokens |
| **Eval Count** | `eval_count` | tokens | Number of tokens generated |
| **Tokens/sec** | `eval_count / (eval_duration / 1e9)` | tokens/sec | Inference throughput |

### Benchmark Script

A reproducible benchmark script is provided at [`scripts/ollama_benchmark.py`](../scripts/ollama_benchmark.py):

```powershell
# Run from project root (requires running Ollama container)
python scripts/ollama_benchmark.py
```

The script sends three standardized prompts to each available model with `"stream": false`, captures the response metrics, and calculates aggregated statistics.

### Reference Benchmark Results

**Test Hardware:** NVIDIA RTX 4070 Laptop GPU (8 GB VRAM), AMD Ryzen 7 7840HS, 32 GB DDR5-5600, NVMe SSD

**Test Prompt:** *"You are a cybersecurity analyst. Analyze the following: An SSH brute force attack from 192.168.1.100 targeting port 22 with 450 failed login attempts over 15 minutes. Provide a 2-paragraph incident summary in Markdown."*

#### GPU-Accelerated Results (NVIDIA RTX 4070)

| Model | Size | VRAM Usage | Cold Load Time | Prompt Eval | Tokens Generated | Inference Speed | Latency/Token |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **mistral:7b** | 4.1 GB | ~4.8 GB | ~2.8 s | ~120 ms | ~185 tokens | **42.5 tok/s** | **23.5 ms** |
| **phi3:3.8b** | 2.2 GB | ~2.9 GB | ~1.6 s | ~85 ms | ~160 tokens | **68.2 tok/s** | **14.7 ms** |
| **gemma:2b** | 1.4 GB | ~2.1 GB | ~1.1 s | ~60 ms | ~140 tokens | **82.0 tok/s** | **12.2 ms** |

#### CPU-Only Results (AMD Ryzen 7, no GPU)

| Model | Size | RAM Usage | Cold Load Time | Prompt Eval | Tokens Generated | Inference Speed | Latency/Token |
|:---|:---|:---|:---|:---|:---|:---|:---|
| **mistral:7b** | 4.1 GB | ~5.2 GB | ~5.4 s | ~850 ms | ~185 tokens | **8.3 tok/s** | **120.5 ms** |
| **phi3:3.8b** | 2.2 GB | ~3.1 GB | ~3.2 s | ~520 ms | ~160 tokens | **14.6 tok/s** | **68.5 ms** |
| **gemma:2b** | 1.4 GB | ~2.4 GB | ~2.0 s | ~350 ms | ~140 tokens | **21.8 tok/s** | **45.9 ms** |

#### Key Observations

1. **GPU provides ~5x throughput improvement** over CPU-only for Mistral 7B (42.5 vs 8.3 tok/s).
2. **Cold start latency** is dominated by model weight loading from disk to VRAM/RAM. Subsequent requests (warm) skip this entirely.
3. **Mistral 7B comfortably fits** in 8 GB VRAM with ~3.2 GB headroom for KV cache and OS overhead.
4. **CPU fallback is viable** for development/testing but not recommended for production inference pipelines.
5. **Inter-token latency** on GPU (23.5 ms) provides smooth streaming UX; CPU (120.5 ms) feels noticeably sluggish.

### Interpreting Your Own Benchmarks

After running the benchmark script, use this formula to calculate tokens/sec from the raw API response:

```
Tokens/sec = eval_count / (eval_duration / 1,000,000,000)
Latency/token (ms) = (eval_duration / eval_count) / 1,000,000
```

---

## 8. Environment Variable Reference

All Sentinel LLM environment variables are defined in `.env` (see `.env.example` for defaults):

| Variable | Default | Description |
|:---|:---|:---|
| `SENTINEL_LLM_ENABLED` | `false` | Master switch — set to `true` to enable Ollama calls |
| `SENTINEL_LLM_HOST` | `http://ollama:11434` | Ollama base URL. Use `http://ollama:11434` in Docker Compose (internal DNS). Use `http://localhost:11434` for native/local Ollama installs. |
| `SENTINEL_LLM_MODEL` | `mistral` | Model name as returned by `ollama list`. Must be pre-pulled. |

### Docker Compose Integration

The API service resolves the Ollama container via Docker internal DNS:

```
API Container → http://ollama:11434 → Ollama Container
```

For **local development** (Ollama running natively outside Docker):

```
.env: SENTINEL_LLM_HOST=http://localhost:11434
```

---

## 9. CPU-Only Fallback Mode

If no NVIDIA GPU is available (e.g., CI/CD runners, AMD-only systems, Apple Silicon via Rosetta):

### Docker Compose Override

Create a `docker-compose.override.yml` to remove GPU requirements:

```yaml
# docker-compose.override.yml — CPU-only fallback
services:
  ollama:
    deploy:
      resources:
        reservations:
          devices: []
        limits:
          memory: 8G
```

### AMD GPU Support (ROCm)

For AMD GPUs, use the ROCm-enabled Ollama image:

```yaml
services:
  ollama:
    image: ollama/ollama:rocm
    container_name: phantomnet_ollama
    devices:
      - /dev/kfd
      - /dev/dri
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - app_net
```

---

## 10. Troubleshooting

### Common Issues

| Symptom | Cause | Resolution |
|:---|:---|:---|
| `could not select device driver "nvidia"` | NVIDIA Container Toolkit not installed or misconfigured | Reinstall toolkit, run `sudo nvidia-ctk runtime configure --runtime=docker`, restart Docker |
| `no nvidia gpu detected` in Ollama logs | GPU not exposed to container | Verify `docker run --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi` works first |
| Model pull hangs or times out | Network issues or disk space | Check `docker exec phantomnet_ollama df -h /root/.ollama` for free space |
| `SENTINEL_LLM_HOST is not set` error | `.env` file missing or `SENTINEL_LLM_ENABLED=true` without host configured | Copy `.env.example` to `.env` and set `SENTINEL_LLM_HOST` |
| API returns empty narrative | `SENTINEL_LLM_ENABLED=false` or Ollama unreachable | Check `docker logs phantomnet_ollama`, verify with `curl http://localhost:11434/` |
| Very slow inference (< 5 tok/s) | Model spilling from VRAM to RAM | Use a smaller model (`phi3:3.8b`) or ensure GPU has sufficient VRAM |
| `Connection refused` from API container | Wrong `SENTINEL_LLM_HOST` value | Use `http://ollama:11434` (Docker DNS), not `localhost` from inside another container |

### Diagnostic Commands

```powershell
# 1. Check container status
docker compose ps

# 2. View Ollama logs (look for GPU detection)
docker logs phantomnet_ollama --tail 50

# 3. Check model storage usage
docker exec phantomnet_ollama du -sh /root/.ollama/models

# 4. Test connectivity from API container
docker exec phantomnet_api curl -s http://ollama:11434/

# 5. Monitor GPU utilization during inference
nvidia-smi -l 1

# 6. Check volume persistence
docker volume inspect phantomnet_ollama_data
```

---

## 11. Security Considerations

### Network Isolation

- The Ollama container is placed on `app_net` only (not `honeypot_net`), preventing direct honeypot-to-LLM communication.
- Port `11434` is exposed to the host for **development only**. In production, remove the port mapping and rely on Docker internal DNS.

### Production Hardening Checklist

- [ ] Remove `ports: "11434:11434"` in production — use internal Docker DNS only
- [ ] Set `restart: unless-stopped` (already configured)
- [ ] Add resource limits to prevent OOM:
  ```yaml
  deploy:
    resources:
      limits:
        memory: 12G
  ```
- [ ] Monitor VRAM usage via `nvidia-smi` dashboards or Prometheus exporters
- [ ] Pin the Ollama image to a specific digest/tag instead of `latest` for reproducibility
- [ ] Never expose the Ollama API to the public internet without authentication

---

## Quick Start Cheat Sheet

```powershell
# 1. Clone & configure
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet
cp .env.example .env
# Edit .env → set SENTINEL_LLM_ENABLED=true

# 2. Start infrastructure
docker compose up -d

# 3. Pull the model
docker exec -it phantomnet_ollama ollama pull mistral

# 4. Verify
curl http://localhost:11434/
docker exec phantomnet_ollama ollama list

# 5. Test inference
curl -X POST http://localhost:11434/api/generate -d '{
  "model": "mistral",
  "prompt": "What is a honeypot?",
  "stream": false
}'

# 6. Run benchmarks
python scripts/ollama_benchmark.py
```

---

*For architectural details on how the LLM service integrates with the Sentinel pipeline, see [`docs/llm_pipeline_architecture.md`](./llm_pipeline_architecture.md).*
