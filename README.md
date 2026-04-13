# SOEN-321 — Secure File Sharing Platform
## Option 2: Design and Analyze a Secure Communication System

### Objective

A web-based encrypted file sharing platform demonstrating core software security concepts:
hybrid encryption (AES-256-GCM / ChaCha20-Poly1305 + RSA-2048 OAEP key wrapping),
cryptographic integrity verification (SHA-256 / SHA-512 / MD5), password hashing (bcrypt),
and key derivation (PBKDF2). The server stores only ciphertext and never persists plaintext or raw keys.

---

### Team Contributions

| Member | GitHub | Student ID | Contributions |
|---|---|---|---|
| Miskat Mahmud | [@codedsami](https://github.com/codedsami) | 40250110 | Login, logout & register routes, Introduction, System Design |
| Adib Akkari | [@adssib](https://github.com/adssib) | 40216815 | System Design, Requirements, DB schema, Sequence Diagrams |
| Shaheer Mohammad | [@Zniniz](https://github.com/Zniniz) | 40252466 | File sharing, deletion & edit routes, Implementation & Security Analysis |
| Omar Elmasaoudi | [@Omare04](https://github.com/Omare04) | 40255123 | Upload, Download, List endpoints + registered files blueprint in app.py |
| Yassine Ibhir | [@Yibhir0](https://github.com/Yibhir0) | 40251116 | Encryption & hashing |
| Tanim Chowdhury | [@Nimzstb](https://github.com/Nimzstb) | 40245607 | Security Analysis and Discussion |
| Ziad-Tarik Taufeek | [@Ziad-Tari](https://github.com/Ziad-Tari) | 40205732 | Worked on the report and validation |


---

### Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask |
| Crypto | PyCA `cryptography` library |
| Auth | Flask-JWT-Extended (JWT Bearer tokens) |
| Database | SQLite via Flask-SQLAlchemy |
| Frontend | Vanilla HTML/CSS/JS + Bootstrap 5 (CDN) |

---

### Project Structure

```
SOEN-321-Project/
├── docs/
│   ├── plantuml/          # PlantUML source files (.puml)
│   └── img/               # Compiled diagram images (.png)
└── secure-file-sharing/
    ├── requirements.txt
    ├── backend/
    │   ├── app.py          # Flask app, route registration, frontend serving
    │   ├── models.py       # SQLAlchemy models: User, File, Share
    │   ├── crypto.py       # All cryptographic primitives
    │   └── routes/
    │       ├── auth.py     # POST /register, POST /login, POST /logout
    │       └── files.py    # File upload, download, delete, share, edit
    └── frontend/
        ├── app.js          # Shared JS utilities (auth, fetch wrapper, navbar)
        ├── index.html      # Login / Register
        ├── dashboard.html  # My Files + Shared With Me
        ├── upload.html     # Encrypt & upload
        ├── download.html   # Decrypt & download + integrity check result
        ├── share.html      # Share file with recipient
        └── edit.html       # Replace file with new encrypted version
```

---

### Prerequisites

- Python 3.10+
- pip

---

### Setup & Run

**1. Clone the repository**
```bash
git clone https://github.com/codedsami/SOEN-321-Project.git
cd SOEN-321-Project
```

**2. Create and activate a virtual environment**
```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r secure-file-sharing/requirements.txt
```

**4. Create a `.env` file inside `secure-file-sharing/backend/`**
```bash
# secure-file-sharing/backend/.env
JWT_SECRET_KEY=your-secret-key-here
```
> Any random string works for development. Example: `JWT_SECRET_KEY=dev-secret-change-in-prod`

**5. Run the server**
```bash
cd secure-file-sharing/backend
python app.py
```

The server starts at **http://127.0.0.1:5000**

**6. Open the UI**

Navigate to **http://127.0.0.1:5000** — it redirects automatically to the login page.

> The frontend is served directly by Flask — no separate server or npm needed.

---

### API Endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/register` | — | Register user, generate RSA-2048 key pair |
| `POST` | `/login` | — | Login, returns JWT |
| `POST` | `/logout` | JWT | Logout (client discards token) |
| `GET` | `/files` | JWT | List owned files (metadata only) |
| `GET` | `/files/shared-with-me` | JWT | List files shared with you |
| `POST` | `/files/upload` | JWT | Encrypt & upload file |
| `DELETE` | `/files/<id>` | JWT | Delete file (owner only) |
| `POST` | `/files/<id>/download` | JWT | Decrypt & download file + integrity check |
| `POST` | `/files/<id>/share` | JWT | Share file with another user |
| `PUT` | `/files/<id>/edit` | JWT | Replace file with new encrypted version |

---

### Compile Diagrams

PlantUML must be installed. To regenerate all PNGs from source:

```bash
plantuml -o ../img docs/plantuml/*.puml
```

---

### Cryptographic Design Summary

| Concern | Primitive | Why |
|---|---|---|
| File encryption | AES-256-GCM or ChaCha20-Poly1305 | AEAD — confidentiality + integrity in one pass |
| Key wrapping | RSA-2048 OAEP | Asymmetric — only key holder can unwrap FEK |
| Password hashing | bcrypt (cost=12) | Slow by design — brute-force resistant |
| Private key protection | PBKDF2-HMAC-SHA256 (100k iter) + AES-256-GCM | Key derivation + authenticated encryption |
| File integrity | SHA-256 / SHA-512 / MD5 | Hash computed before encryption, verified after decryption |
