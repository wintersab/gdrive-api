from flask import Flask, jsonify, send_file, request, abort
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from functools import wraps
from datetime import datetime
import io, os, mimetypes

app = Flask(__name__)

# ======= SSOT CONFIG (Folder lives in a Shared drive) =======
# Keep your known-good SSOT folder ID to avoid env mishaps.
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

# ======= Three-folder lifecycle config =======
# Auto-resolve (or create) /ssot/staging and /ssot/archive under FOLDER_ID.
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
        abort(400, description="invalid 'parents' argument")

    if not pid:
        abort(500, description="parent folder could not be resolved")
    return [pid]

def _enforce_allowed_parents(parents):
    if not parents or parents[0] not in ALLOWED_PARENTS:
        abort(403, description="Parent folder not allowed; must be /ssot, /ssot/staging, or /ssot/archive.")

def _ensure_in_folder(file_id: str, folder_id: str, err="File is not in required folder"):
    meta = drive_service.files().get(
        fileId=file_id, fields="id,parents", supportsAllDrives=True
    ).execute()
    if folder_id not in (meta.get('parents') or []):
        abort(403, description=err)

# ======= Helpers =======
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
        abort(404, description="File not found")
    parents = meta.get('parents') or []
    if FOLDER_ID not in parents:
        abort(403, description="File is not inside the SSOT folder")

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
    """Download a Drive file's bytes (full content fidelity)."""
    req = drive_service.files().get_media(fileId=file_id, supportsAllDrives=True)
    buf = io.BytesIO()
    downloader = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return buf.getvalue()

# ======= Lifecycle helpers: stage → archive → overwrite/promote =======
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
    """Find newest staged *.proposed.* for meta_name in /ssot/staging."""
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
    """
    Back-compat path: archive current, then overwrite authoritative with provided media bytes.
    If staged_id is given, just ensure it's in /ssot/staging (filename no longer required to match).
    """
    _ensure_in_folder(file_id, FOLDER_ID, err="Target is not in /ssot (authoritative)")
    if staged_id:
        _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId is not in /ssot/staging")

    # Explicit archive
    archived = archive_file(file_id)
    if not archived or not archived.get('id'):
        abort(500, description="Archiving failed; aborting overwrite")

    # Overwrite (optionally rename)
    body = {'name': new_name} if new_name else None
    updated = drive_service.files().update(
        fileId=file_id,
        body=body,
        media_body=media_body,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()

    app.logger.info(f"[overwrite] updated {updated.get('name')} ({updated.get('id')}); archived {archived.get('name')}")
    return {"updated": updated, "archived": archived}

def promote_staged_to_authoritative(authoritative_id: str, staged_id: str) -> dict:
    """
    New explicit, verifiable workflow:
      1) Archive the current authoritative file to /ssot/archive with timestamped name.
      2) Promote staged content into authoritative by replacing its bytes (ID and name preserved).
      3) Keep the staged file in /ssot/staging (for audit) — no deletes/moves.
    Returns structured metadata for archived, staged, and updated authoritative.
    """
    # Folder checks
    _ensure_in_folder(authoritative_id, FOLDER_ID, err="authoritativeId must be inside /ssot")
    _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId must be inside /ssot/staging")

    # Get metas (for names)
    auth_meta = drive_service.files().get(
        fileId=authoritative_id, fields="id,name,parents,mimeType,modifiedTime,size", supportsAllDrives=True
    ).execute()
    staged_meta = drive_service.files().get(
        fileId=staged_id, fields="id,name,parents,mimeType,modifiedTime,size", supportsAllDrives=True
    ).execute()

    # 1) Archive authoritative
    archived = archive_file(authoritative_id)

    # 2) Download staged bytes (full fidelity) and write to authoritative
    staged_bytes = _download_bytes(staged_id)
    media = MediaIoBaseUpload(io.BytesIO(staged_bytes), mimetype=staged_meta.get('mimeType') or 'application/octet-stream', resumable=False)

    updated = drive_service.files().update(
        fileId=authoritative_id,
        body=None,  # keep same name
        media_body=media,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()

    # Log clear action transcript
    app.logger.info(f"[promote] archived {auth_meta.get('name')} -> {archived.get('name')}; "
                    f"promoted content from staged {staged_meta.get('name')} into {updated.get('name')}")

    return {
        "actions": ["archived", "promoted", "finalized"],
        "authoritativeBefore": auth_meta,
        "archived": archived,
        "staged": staged_meta,
        "authoritativeAfter": updated
    }

# ======= Routes =======
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
    """List direct children of the SSOT folder (/ssot)."""
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
    """Raw bytes (octet-stream)."""
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
    """Return UTF-8 text for text-like files (best effort)."""
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
    multipart/form-data:
      - file (binary, required)
      - name (optional)
      - parents (optional; 'ssot'|'staging'|'archive' or folderId; defaults to /ssot)
      - confirm (required via guard)
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        name = request.form.get('name') or (up.filename or 'untitled')
        if not allowed_name_and_mime(name, up.mimetype):
            return jsonify({"error": "file type not allowed"}), 415

        parents = _resolve_parents_arg(request.form.getlist('parents') or request.form.get('parents'))
        _enforce_allowed_parents(parents)

        media = MediaIoBaseUpload(up.stream, mimetype=(up.mimetype or guess_mime_from_name(name)), resumable=False)
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
    multipart/form-data:
      - file (binary, required)
      - name (optional rename; must be allowed)
      - mode (optional; 'staging' or 'overwrite') — defaults to WRITE_MODE
      - stagedId (optional; used for overwrite compliance if you want to bind a specific staged file)
      - confirm (required via guard)
    Lifecycle rules:
      - staging: write *.proposed.<ts> into /ssot/staging
      - overwrite: archive current to /ssot/archive; then update /ssot (no filename coupling)
    """
    try:
        ensure_in_ssot(file_id)  # Target must be inside /ssot

        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        new_name = request.form.get('name')
        mode = (request.form.get('mode') or WRITE_MODE).lower()
        staged_id = request.form.get('stagedId')

        meta = drive_service.files().get(
            fileId=file_id, fields="id,name,parents,mimeType", supportsAllDrives=True
        ).execute()

        target_name = new_name or meta['name']
        target_mime = up.mimetype or guess_mime_from_name(target_name)
        if not allowed_name_and_mime(target_name, target_mime):
            return jsonify({"error": "file type not allowed"}), 415

        media = MediaIoBaseUpload(up.stream, mimetype=target_mime, resumable=False)

        if mode == 'staging':
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        # overwrite with explicit archive
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
    JSON body:
      - name (required)
      - content (required, UTF-8)
      - mimeType (optional; default text/plain)
      - parents (optional; 'ssot'|'staging'|'archive' or folderId; defaults to /ssot)
      - confirm (required via guard)
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
        if len((content or '').encode('utf-8')) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        parents = _resolve_parents_arg(parents_arg)
        _enforce_allowed_parents(parents)

        media = text_upload_media(content, mime)
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
    JSON body:
      - content (required)
      - mimeType (optional; default text/plain)
      - name (optional rename; applied only at overwrite)
      - mode (optional; 'staging'|'overwrite') — defaults to WRITE_MODE
      - stagedId (optional; used for overwrite compliance if binding to a specific staged item)
      - confirm (required via guard)
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
        if len((content or '').encode('utf-8')) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        meta = drive_service.files().get(
            fileId=file_id, fields="id,name,parents,mimeType", supportsAllDrives=True
        ).execute()

        target_name = new_name or meta['name']
        if not allowed_name_and_mime(target_name, mime):
            return jsonify({"error": "file type not allowed"}), 415

        media = text_upload_media(content, mime)

        if mode == 'staging':
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
    """Rename without changing content (authoritative only)."""
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

# ---- PROMOTE (explicit archive → promote) ----
@app.route('/promote', methods=['POST'])
@require_api_key(write=True)
def promote():
    """
    Promote a staged SSOT file into authoritative with explicit archival.
    JSON body:
      - authoritativeId (required): fileId of the authoritative file in /ssot
      - stagedId (required): fileId of the staged file in /ssot/staging
      - confirm (required via guard)
    Returns: structured metadata (archived, staged, authoritativeBefore/After, actions)
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
    # Render usually honors port 8080, but this also works if PORT is provided.
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '8080')))
