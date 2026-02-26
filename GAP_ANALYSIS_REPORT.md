# Software Development Gap Analysis

## SOFTWARE DEVELOPMENT REQUIREMENT VERDICT

**Additional software development is required: YES**

The following components require code modification to meet the strict requirements of OCI Free Tier deployment (Distributed VMs, Statelessness, External Frontend).

| Component | Reason for Development | Type | Complexity | Blocking? |
| :--- | :--- | :--- | :--- | :--- |
| **Log Generator** | Currently implemented as an internal library imported by the Detector. To run on a separate VM (VM1), it must be refactored into a standalone service that pushes data via API/HTTP. | **Refactor** | Medium | **YES** |
| **Frontend** | API URL is hardcoded to `http://localhost:8000` in `useAuth.js` and `useSecurityDashboard.js`. Must be refactored to use Environment Variables (`VITE_API_BASE`). | **Refactor** | Low | **YES** |
| **Auth Service** | Relies on local filesystem (`users.json`) for user persistence. This violates "Statelessness" and will fail if the backend restarts on a fresh instance without persistent block storage. Must migrate to MongoDB. | **Refactor** | Low | **YES** |
| **Threat Persistence** | Primary persistence is local `threats.json` with MongoDB as a "supported" option but often fallback-driven. Code prioritizes local cache in some paths. Must enforce MongoDB-first for production. | **Refactor** | Low | **No** |

## DETAILED ANALYSIS

### 1. Functional Completeness Check
- **Log Generator (VM1) & Detector (VM2)**: **FAIL**. The current codebase runs them in a single process (`run_live_detection.py` imports `log_generator`). They cannot be deployed to separate VMs without refactoring the communication layer (e.g., Generator sends HTTP POST to Detector).
- **Storage Interface**: **PASS**. `OCIStorageManager` class is implemented.
- **Frontend Integration**: **PARTIAL**. Code exists, but hardcoded to localhost.

### 2. Cloud-Readiness Code Review
- **Hardcoded IPs/URLs**: **FAIL**.
  - `frontend/src/hooks/useAuth.js`: Line 33 `http://localhost:8000/api/auth/login`
  - `frontend/src/hooks/useSecurityDashboard.js`: Line 12 `const API_BASE = 'http://localhost:8000/api';`
- **Statelessness**: **FAIL**. `auth_service.py` writes to `users.json` on the ephemeral container filesystem.

### 3. Scalability & Reliability
- **Restart Logic**: **PASS**. Systemd service handles process restarts.
- **Buffers**: **PASS**. `run_live_detection.py` implements an archival buffer.

### 4. Security Implementation
- **Mechanisms**: **PASS**. JWT implementation (`backend/core/security.py`) and `auth_service.py` logic are sound.
- **Persistence**: **FAIL**. Storing credentials in `users.json` is a risk in ephemeral environments (data loss).

### 5. ML Lifecycle Separation
- **Separation**: **PASS**. `trainer.py` is a distinct script from `detector.py`. Inference engine loads a pre-trained `.pkl` file.

## RECOMMENDATIONS
1.  **Refactor Frontend**: Replace localhost strings with `import.meta.env.VITE_API_URL`.
2.  **Decouple Generator**: Create `backend/run_generator_standalone.py` that loops and POSTs data to `POST /api/telemetry` (needs new endpoint on backend).
3.  **Migrate Auth**: Update `AuthService` to read/write from `db.collection('users')` instead of JSON.
