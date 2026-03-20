# SceneAI Production — PWA Edition

AI-powered scene detection and viral clip analysis.  
Multi-user, job-queue architecture. Installable as PWA.

## Quick Start

```bash
# 1. Install dependencies
pip3 install opencv-python numpy

# 2. Run the server
python3 sceneai_server.py

# 3. Open browser
# http://127.0.0.1:7842
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Browser (PWA)                     │
│  Upload → Create Job → Poll Status → View Results   │
└────────────────────┬────────────────────────────────┘
                     │ HTTP
┌────────────────────▼────────────────────────────────┐
│              sceneai_server.py                       │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ Job Store   │  │ ThreadPool   │  │  Security  │  │
│  │ (per-user)  │  │ (N workers)  │  │  Layer     │  │
│  └──────┬──────┘  └──────┬───────┘  └────────────┘  │
│         │                │                           │
│  ┌──────▼────────────────▼───────────────────────┐  │
│  │              Analysis Pipeline                 │  │
│  │  FFmpeg pipe → Motion scoring → Thumbnails    │  │
│  │  → Transcription (Whisper) → Results JSON     │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## API Endpoints

### Job-Based (new)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload video file |
| POST | `/api/jobs` | Create analysis job |
| GET | `/api/jobs` | List all jobs |
| GET | `/api/jobs/{id}/status` | Poll job progress |
| GET | `/api/jobs/{id}/results` | Get results JSON |
| GET | `/api/jobs/{id}/thumbnail/{sceneId}` | Get scene thumbnail |
| GET | `/api/jobs/{id}/stream/clip?start=&end=` | Stream clip segment |
| GET | `/api/jobs/{id}/stream/video` | Stream full video (Range) |
| POST | `/api/jobs/{id}/cancel` | Cancel running job |
| POST | `/api/jobs/{id}/retry` | Retry failed job |
| DELETE | `/api/jobs/{id}` | Delete job + file |
| GET | `/api/download/{filename}` | Download export file |

### Legacy (backward compatible)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/analyze/start` | Start analysis (path-based) |
| GET | `/api/analyze/status` | Get latest job status |
| GET | `/api/results` | Get latest results |

### Export & AI
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/export/short-form` | Generate 9:16 clip |
| POST | `/api/export/montage` | Build highlight montage |
| POST | `/api/search/natural` | AI natural language search |

## Security Features

- **File validation**: extension, magic bytes, size limit (default 4 GB)
- **Filename sanitization**: strips path traversal, removes unsafe chars
- **Rate limiting**: 30 requests/minute per IP (configurable)
- **Path containment**: all uploaded files confined to temp directory
- **Injection prevention**: FFmpeg args never contain user-controlled strings
- **Security headers**: X-Content-Type-Options, X-Frame-Options on all responses

## Configuration (Environment Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `SCENEAI_MAX_MB` | `4096` | Max upload size in MB |
| `SCENEAI_MAX_JOBS` | `50` | Max jobs to keep in memory |
| `SCENEAI_RATE_RPM` | `30` | Rate limit per IP per minute |
| `ANTHROPIC_API_KEY` | — | Enable AI natural language search |

## PWA Installation

1. Open `http://127.0.0.1:7842` in Chrome/Edge
2. Click the install banner or use browser menu → "Install SceneAI"
3. App runs as standalone window with offline shell

## Optional Dependencies

```bash
# Faster transcription (GPU-accelerated)
pip3 install faster-whisper

# Standard Whisper fallback
pip3 install openai-whisper

# FFmpeg (required)
brew install ffmpeg       # macOS
sudo apt install ffmpeg   # Ubuntu
```

## File Structure

```
sceneai_pwa/
├── sceneai_server.py        ← Production backend
└── frontend/
    ├── index.html           ← PWA frontend
    ├── manifest.json        ← PWA manifest
    ├── sw.js                ← Service worker
    └── offline.html         ← Offline fallback
```
