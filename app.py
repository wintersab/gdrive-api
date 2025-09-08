from flask import Flask, jsonify, send_file, request, abort
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from functools import wraps
from datetime import datetime
import io, os, mimetypes, json, re

# Optional YAML validation (best-effort)
try:
    import yaml  # PyYAML (optional); if not present, YAML check will degrade gracefully
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

app = Flask(__name__)

# ======= SSOT CONFIG (Folder lives in a Shared drive) =======
# Keep your known-good SSOT folder ID (baseline retained) :contentReference[oaicite:2]{index=2}
FOLDER_ID = '1Ox7DXcd9AEvF84FkCVyB90MGHR0v7q7R'  # /ssot (authoritative)

# ======= Google Drive API =======
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
drive_service = build('drive', 'v3', credentials=credentials)

# ======= Guardrails / Ops Controls (Render → Environment) =======
API_KEY = os.getenv('API_KEY')  # required for all routes
READ_ONLY = os.getenv('READ_ONLY', 'true').lower() == 'true'
WRITE_CONFIRM_PHRASE = os.getenv('WRITE_CONFIRM_PHRASE')
WRITE_MODE = os.getenv('WRITE_MODE', 'staging').lower()  # default; can be overridden per-request via "mode"

# Max request body size (default 2MB).
MAX_BYTES = int(os.getenv('MAX_BYTES', '2000000'))
app.config['MAX_CONTENT_LENGTH'] = MAX_BYTES

# ======= File type allowlist =======
ALLOWED_EXTS = {'.txt', '.md', '.markdown', '.yml', '.yaml', '.json', '.csv', '.docx'}
ALLOWED_MIMES = {
    'text/plain', 'text/markdown', 'text/x-markdown',
    'application/x-yaml', 'text/yaml',
    'application/json', 'text/csv',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}
mimetypes.init()

# ======= Three-folder lifecycle config (baseline retained) =======
def _ensure_subfolder(parent_id: str, name: str) -> str:
    q = (
        f"'{parent_id}' in parents and "
        f"name = '{name}' and "
        f"mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    )
    res = drive_service.files().list(
        q=q, includeItemsFromAllDrives=True, supportsAllDrives=True, fields="files(id,name)"
    ).execute()
    if res.get('files'):
        return res['files'][0]['id']
    created = drive_service.files().create(
        body={'name': name, 'mimeType': 'application/vnd.google-apps.folder', 'parents': [parent_id]},
        fields="id", supportsAllDrives=True
    ).execute()
    return created['id']

STAGING_FOLDER_ID = _ensure_subfolder(FOLDER_ID, 'staging')   # /ssot/staging
ARCHIVE_FOLDER_ID = _ensure_subfolder(FOLDER_ID, 'archive')   # /ssot/archive
ALLOWED_PARENTS = {FOLDER_ID, STAGING_FOLDER_ID, ARCHIVE_FOLDER_ID}

def _resolve_parents_arg(parents_arg):
    """
    Accepts:
      - None
      - 'ssot' | 'staging' | 'archive'
      - folderId
      - ['ssot'|'staging'|'archive'] or [folderId]
    Returns: [<validated folderId>]
    """
    def _map_token(token):
        t = str(token or '').strip().lower()
        if t in ('ssot', '/ssot'):
            return FOLDER_ID
        if t in ('staging', '/ssot/staging'):
            return STAGING_FOLDER_ID
        if t in ('archive', 'archived', '/ssot/archive'):
            return ARCHIVE_FOLDER_ID
        return token  # assume a folderId

    if not parents_arg:
        pid = FOLDER_ID
    elif isinstance(parents_arg, str):
        pid = _map_token(parents_arg)
    elif isinstance(parents_arg, list) and parents_arg:
        pid = _map_token(parents_arg[0])
    else:
        return abort(400, description="invalid 'parents' argument")

    if not pid:
        return abort(500, description="parent folder could not be resolved")
    return [pid]

def _enforce_allowed_parents(parents):
    if not parents or parents[0] not in ALLOWED_PARENTS:
        return abort(403, description="Parent folder not allowed; must be /ssot, /ssot/staging, or /ssot/archive.")

def _ensure_in_folder(file_id: str, folder_id: str, err="File is not in required folder"):
    meta = drive_service.files().get(
        fileId=file_id, fields="id,parents", supportsAllDrives=True
    ).execute()
    if folder_id not in (meta.get('parents') or []):
        return abort(403, description=err)

# ======= Staging "complete document" validator =======
CONFLICT_MARKERS = ('<<<<<<<', '=======', '>>>>>>>')
PATCH_MARKERS_RE = re.compile(r'^(diff --git|Index: |\*\*\* |--- [ab]/|\+\+\+ [ab]/|@@ )', re.MULTILINE)

def _ext(name): return os.path.splitext(name or '')[1].lower()
def _is_texty(mime, name):
    ext = _ext(name)
    return (mime or '').startswith('text/') or (mime in {'application/x-yaml','text/yaml','application/json'}) or (ext in {'.yml','.yaml','.md','.markdown','.json','.csv','.txt'})

def _looks_like_patch_or_diff(text: str) -> bool:
    if not text:
        return True
    if PATCH_MARKERS_RE.search(text):
        return True
    if any(m in text for m in CONFLICT_MARKERS):
        return True
    # heavy +/- lines typical of patches (exclude YAML/MD lists "- ")
    lines = [ln for ln in text.splitlines()[:200]]
    plus_minus = sum(1 for ln in lines if (ln.startswith('+') or (ln.startswith('-') and not ln.startswith('- '))))
    return (plus_minus >= max(5, int(0.3 * (len(lines) or 1))))

def _validate_full_document_for_staging(name: str, mime: str, content_bytes: bytes):
    # 1) Must be non-empty
    if not content_bytes or len(content_bytes) == 0:
        return abort(422, description="stagingRequiresFullDocument: empty content not allowed")
    # 2) Only validate text-like formats
    if not _is_texty(mime, name):
        # Allow binary like .docx without deep validation
        return
    try:
        text = content_bytes.decode('utf-8', errors='replace')
    except Exception:
        return abort(422, description="stagingRequiresFullDocument: content must be UTF-8 text for text formats")

    # 3) Block obvious diffs/patches/merge fragments
    if _looks_like_patch_or_diff(text):
        return abort(422, description="stagingRequiresFullDocument: detected diff/patch/fragment; submit a full file")

    ext = _ext(name)

    # 4) Light structural checks per type
    if ext in ('.yml', '.yaml'):
        if HAVE_YAML:
            try:
                parsed = yaml.safe_load(text)
            except Exception:
                return abort(422, description="stagingRequiresFullDocument: invalid YAML; submit well-formed YAML")
            if parsed is None:
                return abort(422, description="stagingRequiresFullDocument: YAML is empty; submit complete document")
        # if PyYAML not available, we already passed text/diff checks
    elif ext == '.json':
        try:
            json.loads(text)
        except Exception:
            return abort(422, description="stagingRequiresFullDocument: invalid JSON; submit full JSON document")
    elif ext == '.csv':
        # very light CSV heuristic: at least 2 lines or one line with delimiter
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines or (len(lines) == 1 and (',' not in lines[0] and '\t' not in lines[0])):
            return abort(422, description="stagingRequiresFullDocument: CSV appears incomplete; submit full table")

# ======= Helpers (auth, mime, staging/archive/overwrite) — baseline retained and extended :contentReference[oaicite:3]{index=3}
def require_api_key(write=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            provided = request.headers.get('X-API-Key')
            if not API_KEY or provided != API_KEY:
                return jsonify({'error': 'unauthorized'}), 401
            if write:
                if READ_ONLY:
                    return jsonify({'error': 'read-only mode: writes are disabled'}), 403
                confirm = None
                if request.is_json:
                    data = request.get_json(silent=True) or {}
                    confirm = data.get('confirm')
                confirm = confirm or request.form.get('confirm') or request.headers.get('X-Write-Confirm')
                if not WRITE_CONFIRM_PHRASE or confirm != WRITE_CONFIRM_PHRASE:
                    return jsonify({'error': 'missing or invalid confirmation phrase'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def guess_mime_from_name(name: str) -> str:
    mime, _ = mimetypes.guess_type(name)
    return mime or 'application/octet-stream'

def allowed_name_and_mime(name: str, mime):
    ext = os.path.splitext(name or '')[1].lower()
    if ext not in ALLOWED_EXTS:
        return False
    mime = mime or guess_mime_from_name(name)
    if mime in ALLOWED_MIMES:
        return True
    if ext in {'.md', '.markdown'} and mime.startswith('text/'):
        return True
    if ext in {'.yml', '.yaml'} and (mime.startswith('text/') or mime == 'application/octet-stream'):
        return True
    if ext in {'.txt', '.json', '.csv'} and mime.startswith('text/'):
        return True
    return False

def ensure_in_ssot(file_id: str):
    """Abort 403 if target file is not directly inside the SSOT folder."""
    try:
        meta = drive_service.files().get(
            fileId=file_id, fields="id, parents", supportsAllDrives=True
        ).execute()
    except Exception:
        return abort(404, description="File not found")
    parents = meta.get('parents') or []
    if FOLDER_ID not in parents:
        return abort(403, description="File is not inside the SSOT folder")

def text_upload_media(content: str, mime: str):
    b = (content or '').encode('utf-8')
    bio = io.BytesIO(b)
    return MediaIoBaseUpload(bio, mimetype=mime or 'text/plain', resumable=False)

def now_stamp():
    return datetime.utcnow().strftime('%Y%m%d-%H%M%S')

def _archive_stamp():
    # <YYYY-MM-DD-HHMM> for governance naming in /ssot/archive
    return datetime.utcnow().strftime('%Y-%m-%d-%H%M')

def _download_bytes(file_id: str) -> bytes:
    req = drive_service.files().get_media(fileId=file_id, supportsAllDrives=True)
    buf = io.BytesIO()
    downloader = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return buf.getvalue()

# ======= Lifecycle helpers: stage → archive → overwrite/promote (baseline pattern) :contentReference[oaicite:4]{index=4}
def stage_file(source_name: str, media_body):
    """Create *.proposed.<timestamp> in /ssot/staging/"""
    proposed_name = f"{source_name}.proposed.{now_stamp()}"
    created = drive_service.files().create(
        body={'name': proposed_name, 'parents': [STAGING_FOLDER_ID]},
        media_body=media_body,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()
    return created

def archive_file(file_id: str) -> dict:
    """Copy current authoritative into /ssot/archive/ with <name>.<YYYY-MM-DD-HHMM>.<ext>"""
    _ensure_in_folder(file_id, FOLDER_ID, err="Can only archive items from /ssot")
    meta = drive_service.files().get(
        fileId=file_id, fields="id,name,parents", supportsAllDrives=True
    ).execute()
    base, ext = os.path.splitext(meta['name'])
    stamped = f"{base}.{_archive_stamp()}{ext}"
    archived = drive_service.files().copy(
        fileId=file_id,
        body={'name': stamped, 'parents': [ARCHIVE_FOLDER_ID]},
        supportsAllDrives=True,
        fields="id,name,parents,modifiedTime,size"
    ).execute()
    app.logger.info(f"[archive] {meta['name']} -> /archive as {stamped} ({archived.get('id')})")
    return archived

def _find_staged_for(meta_name: str):
    q = (
        f"'{STAGING_FOLDER_ID}' in parents and trashed = false and "
        f"mimeType != 'application/vnd.google-apps.folder' and "
        f"name contains '{meta_name}.proposed.'"
    )
    res = drive_service.files().list(
        q=q, includeItemsFromAllDrives=True, supportsAllDrives=True,
        fields="files(id,name,modifiedTime,size)"
    ).execute()
    files = res.get('files', [])
    if not files:
        return None
    return max(files, key=lambda f: f.get('modifiedTime', ''))

def overwrite_file(file_id: str, media_body, new_name: str = None, staged_id: str = None):
    """Archive current, then overwrite authoritative with provided media bytes (back-compat overwrite)."""
    _ensure_in_folder(file_id, FOLDER_ID, err="Target is not in /ssot (authoritative)")
    if staged_id:
        _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId is not in /ssot/staging")
    archived = archive_file(file_id)
    if not archived or not archived.get('id'):
        return abort(500, description="Archiving failed; aborting overwrite")
    body = {'name': new_name} if new_name else None
    updated = drive_service.files().update(
        fileId=file_id, body=body, media_body=media_body,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()
    app.logger.info(f"[overwrite] updated {updated.get('name')} ({updated.get('id')}); archived {archived.get('name')}")
    return {"updated": updated, "archived": archived}

def promote_staged_to_authoritative(authoritative_id: str, staged_id: str) -> dict:
    """
    Explicit workflow:
      1) Archive the current authoritative file to /ssot/archive (timestamped).
      2) Replace authoritative bytes with the staged file's bytes (name/ID preserved).
      3) Keep the staged file for audit.
      4) (New) Validate staged bytes are a complete document before promotion.
    """
    _ensure_in_folder(authoritative_id, FOLDER_ID, err="authoritativeId must be inside /ssot")
    _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId must be inside /ssot/staging")

    auth_meta = drive_service.files().get(
        fileId=authoritative_id, fields="id,name,parents,mimeType,modifiedTime,size", supportsAllDrives=True
    ).execute()
    staged_meta = drive_service.files().get(
        fileId=staged_id, fields="id,name,parents,mimeType,modifiedTime,size", supportsAllDrives=True
    ).execute()

    # Validate staged file is a complete document
    staged_bytes = _download_bytes(staged_id)
    _validate_full_document_for_staging(staged_meta.get('name') or '', staged_meta.get('mimeType') or '', staged_bytes)

    archived = archive_file(authoritative_id)
    media = MediaIoBaseUpload(io.BytesIO(staged_bytes),
                              mimetype=staged_meta.get('mimeType') or 'application/octet-stream',
                              resumable=False)
    updated = drive_service.files().update(
        fileId=authoritative_id, body=None, media_body=media,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()

    app.logger.info(f"[promote] archived {auth_meta.get('name')} -> {archived.get('name')}; "
                    f"promoted content from staged {staged_meta.get('name')} into {updated.get('name')}")

    return {
        "actions": ["archived", "promoted", "finalized"],
        "authoritativeBefore": auth_meta,
        "archived": archived,
        "staged": staged_meta,
        "authoritativeAfter": updated
    }

# ======= Error -> JSON for 422 =======
@app.errorhandler(422)
def handle_422(e):
    return jsonify({"error": getattr(e, "description", "Unprocessable Entity")}), 422

# ======= Routes (baseline retained, with staging validation added where applicable) =======
@app.route('/', methods=['GET'])
def index():
    return "GDrive SSOT API is running. Try /healthz and /files", 200

@app.route('/healthz', methods=['GET'])
@require_api_key(write=False)
def healthz():
    try:
        about = drive_service.about().get(fields="user(emailAddress)").execute()
        return {
            "status": "ok",
            "as": about.get("user", {}).get("emailAddress"),
            "readOnly": READ_ONLY,
            "writeMode": WRITE_MODE,
            "maxBytes": MAX_BYTES,
            "authoritativeFolderId": FOLDER_ID,
            "stagingFolderId": STAGING_FOLDER_ID,
            "archiveFolderId": ARCHIVE_FOLDER_ID
        }, 200
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500

# ---- READ ----
@app.route('/files', methods=['GET'])
@require_api_key(write=False)
def list_files():
    try:
        results = drive_service.files().list(
            q=f"'{FOLDER_ID}' in parents AND trashed = false",
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            fields="files(id,name,mimeType,parents,modifiedTime,size)"
        ).execute()
        return jsonify(results.get('files', [])), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>/content', methods=['GET'])
@require_api_key(write=False)
def get_file_content(file_id):
    try:
        req = drive_service.files().get_media(fileId=file_id, supportsAllDrives=True)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, req)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        fh.seek(0)
        return send_file(fh, as_attachment=False, download_name="file")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>/text', methods=['GET'])
@require_api_key(write=False)
def get_file_text(file_id):
    try:
        meta = drive_service.files().get(
            fileId=file_id, fields="id,name,mimeType", supportsAllDrives=True
        ).execute()
        req = drive_service.files().get_media(fileId=file_id, supportsAllDrives=True)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, req)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        text = fh.getvalue().decode('utf-8', errors='replace')
        return jsonify({"id": meta["id"], "name": meta["name"], "mimeType": meta.get("mimeType", ""), "text": text}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- CREATE (Binary) ----
@app.route('/files', methods=['POST'])
@require_api_key(write=True)
def upload_file():
    """
    Upload a new file into /ssot, /ssot/staging, or /ssot/archive.
    Enforces 'full document' policy when parents resolves to /ssot/staging.
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        raw = up.read()  # bytes for validation & upload
        name = request.form.get('name') or (up.filename or 'untitled')
        mime = up.mimetype or guess_mime_from_name(name)

        if not allowed_name_and_mime(name, mime):
            return jsonify({"error": "file type not allowed"}), 415
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        parents = _resolve_parents_arg(request.form.getlist('parents') or request.form.get('parents'))
        _enforce_allowed_parents(parents)

        # Staging Policy: staging files must be complete docs
        if parents[0] == STAGING_FOLDER_ID:
            _validate_full_document_for_staging(name, mime, raw)

        media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)
        created = drive_service.files().create(
            body={'name': name, 'parents': parents},
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(created), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- UPDATE (Binary) ----
@app.route('/files/<file_id>', methods=['PATCH'])
@require_api_key(write=True)
def update_file(file_id):
    """
    Replace contents of an existing authoritative file (binary).
    Staging mode writes *.proposed.<ts> into /ssot/staging and enforces full-document policy.
    Overwrite mode archives current then updates authoritative.
    """
    try:
        ensure_in_ssot(file_id)

        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        raw = up.read()
        new_name = request.form.get('name')
        mode = (request.form.get('mode') or WRITE_MODE).lower()
        staged_id = request.form.get('stagedId')

        meta = drive_service.files().get(
            fileId=file_id, fields="id,name,parents,mimeType", supportsAllDrives=True
        ).execute()
        target_name = new_name or meta['name']
        mime = up.mimetype or guess_mime_from_name(target_name)

        if not allowed_name_and_mime(target_name, mime):
            return jsonify({"error": "file type not allowed"}), 415
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)

        if mode == 'staging':
            _validate_full_document_for_staging(target_name, mime, raw)
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        result = overwrite_file(file_id, media, new_name, staged_id)
        return jsonify({"mode": "overwrite", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- CREATE (Text JSON) ----
@app.route('/files/text', methods=['POST'])
@require_api_key(write=True)
def create_text_file():
    """
    Create a new text-like file from JSON.
    If parents resolves to /ssot/staging, enforces 'full document' staging policy.
    """
    try:
        data = request.get_json(silent=True) or {}
        name = data.get('name')
        content = data.get('content')
        mime = data.get('mimeType') or 'text/plain'
        parents_arg = data.get('parents')
        if not name or content is None:
            return jsonify({"error": "missing 'name' or 'content'"}), 400
        if not allowed_name_and_mime(name, mime):
            return jsonify({"error": "file type not allowed"}), 415
        raw = (content or '').encode('utf-8')
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        parents = _resolve_parents_arg(parents_arg)
        _enforce_allowed_parents(parents)

        if parents[0] == STAGING_FOLDER_ID:
            _validate_full_document_for_staging(name, mime, raw)

        media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)
        created = drive_service.files().create(
            body={'name': name, 'parents': parents},
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(created), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- UPDATE (Text JSON) ----
@app.route('/files/<file_id>/text', methods=['PATCH'])
@require_api_key(write=True)
def update_text_file(file_id):
    """
    Update an existing authoritative file from JSON text content.
    In staging mode, enforces 'full document' policy before creating a *.proposed.<ts>.
    """
    try:
        ensure_in_ssot(file_id)

        data = request.get_json(silent=True) or {}
        content = data.get('content')
        mime = data.get('mimeType') or 'text/plain'
        new_name = data.get('name')
        mode = (data.get('mode') or WRITE_MODE).lower()
        staged_id = data.get('stagedId')

        if content is None:
            return jsonify({"error": "missing 'content'"}), 400
        raw = (content or '').encode('utf-8')
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        meta = drive_service.files().get(
            fileId=file_id, fields="id,name,parents,mimeType", supportsAllDrives=True
        ).execute()

        target_name = new_name or meta['name']
        if not allowed_name_and_mime(target_name, mime):
            return jsonify({"error": "file type not allowed"}), 415

        media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)

        if mode == 'staging':
            _validate_full_document_for_staging(target_name, mime, raw)
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        result = overwrite_file(file_id, media, new_name, staged_id)
        return jsonify({"mode": "overwrite", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- METADATA ONLY (Rename) ----
@app.route('/files/<file_id>/metadata', methods=['PATCH'])
@require_api_key(write=True)
def rename_file(file_id):
    try:
        ensure_in_ssot(file_id)
        data = request.get_json(silent=True) or {}
        new_name = data.get('name')
        if not new_name:
            return jsonify({"error": "missing 'name'"}), 400
        if not allowed_name_and_mime(new_name, None):
            return jsonify({"error": "file type not allowed"}), 415

        updated = drive_service.files().update(
            fileId=file_id,
            body={'name': new_name},
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(updated), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- STAGING CLEANUP (scoped to /ssot/staging) ----
@app.route('/staging/cleanup', methods=['POST'])
@require_api_key(write=True)
def cleanup_staging():
    """
    Deletes ALL files inside /ssot/staging (not folders).
    Leaves /ssot and /ssot/archive untouched.
    """
    try:
        q = (
            f"'{STAGING_FOLDER_ID}' in parents and trashed = false and "
            f"mimeType != 'application/vnd.google-apps.folder'"
        )
        res = drive_service.files().list(
            q=q, includeItemsFromAllDrives=True, supportsAllDrives=True, fields="files(id,name)"
        ).execute()
        files = res.get('files', [])
        for f in files:
            drive_service.files().delete(fileId=f['id']).execute()
        return jsonify({"deleted": len(files)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- PROMOTE (archive → promote) ----
@app.route('/promote', methods=['POST'])
@require_api_key(write=True)
def promote():
    """
    Promote a staged SSOT file into authoritative with explicit archival.
    Also validates the staged file is a full document before promotion.
    """
    try:
        data = request.get_json(silent=True) or {}
        authoritative_id = data.get('authoritativeId')
        staged_id = data.get('stagedId')
        if not authoritative_id or not staged_id:
            return jsonify({"error": "missing 'authoritativeId' or 'stagedId'"}), 400

        result = promote_staged_to_authoritative(authoritative_id, staged_id)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- Debug (optional) ----
@app.route('/debug/folder', methods=['GET'])
@require_api_key(write=False)
def debug_folder():
    try:
        meta = drive_service.files().get(
            fileId=FOLDER_ID,
            fields="id,name,mimeType,driveId,parents",
            supportsAllDrives=True
        ).execute()
        return meta, 200
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8080')))
