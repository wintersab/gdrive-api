import os
import io
import base64
import mimetypes
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, send_file, request, abort
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)

# -----------------------------
# Core SSOT config
# -----------------------------
# Authoritative SSOT folder (Google Drive folderId).
# Prefer setting via environment variable FOLDER_ID in Render.
FOLDER_ID = os.getenv('FOLDER_ID', '1Ox7DXcd9AEvF84FkCVyB90MGHR0v7q7R')  # /ssot

# Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'  # provided via Render Secret File
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
drive_service = build('drive', 'v3', credentials=credentials)

# -----------------------------
# Guardrails / Ops Controls
# -----------------------------
API_KEY = os.getenv('kAzfotY2XTmNQiDQWUn5HX48IQbM5hYHwnrNdTf4eGuu8an3AAEN3gAqqpCtDzjpkjB3F4gGczOBypGo9qYrAgnXzGjNEvE4XMWgSHgeXZYZ8zlD249lStYCIlt7BX7c
')  # required
READ_ONLY = os.getenv('READ_ONLY', 'true').lower() == 'true'
WRITE_CONFIRM_PHRASE = os.getenv('popex_approved')
WRITE_MODE = os.getenv('WRITE_MODE', 'staging').lower()  # 'staging' or 'overwrite'

# Maximum request size (bytes) for uploads / text bodies
MAX_BYTES = int(os.getenv('MAX_BYTES', '2000000'))
app.config['MAX_CONTENT_LENGTH'] = MAX_BYTES

# -----------------------------
# File type allowlist
# -----------------------------
ALLOWED_EXTS = {'.txt', '.md', '.markdown', '.yml', '.yaml', '.json', '.csv', '.docx'}
ALLOWED_MIMES = {
    'text/plain', 'text/markdown', 'text/x-markdown',
    'application/x-yaml', 'text/yaml',
    'application/json', 'text/csv',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}
mimetypes.init()


# -----------------------------
# Helper: extract API key (X-API-Key, Authorization: Bearer/Basic)
# -----------------------------
def _extract_api_key_from_headers():
    # 1) Custom header
    key = request.headers.get('X-API-Key')
    if key:
        return key

    # 2) Authorization: Bearer <key>
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth.split(' ', 1)[1].strip()

    # 3) Authorization: Basic base64(key:) or base64(key)
    if auth.startswith('Basic '):
        try:
            raw = base64.b64decode(auth.split(' ', 1)[1]).decode('utf-8')
            return raw.split(':', 1)[0].strip()
        except Exception:
            return None
    return None


def require_api_key(write=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            provided = _extract_api_key_from_headers()
            if not API_KEY or provided != API_KEY:
                return jsonify({'error': 'unauthorized'}), 401
            if write:
                if READ_ONLY:
                    return jsonify({'error': 'read-only mode: writes are disabled'}), 403
                # confirmation phrase may be in JSON, form, or header
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


# -----------------------------
# Helpers: mimetypes / size / time
# -----------------------------
def guess_mime_from_name(name: str) -> str:
    mime, _ = mimetypes.guess_type(name)
    return mime or 'application/octet-stream'


def allowed_name_and_mime(name: str, mime: str | None) -> bool:
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


def text_upload_media(content: str, mime: str):
    b = (content or '').encode('utf-8')
    bio = io.BytesIO(b)
    return MediaIoBaseUpload(bio, mimetype=mime or 'text/plain', resumable=False)


def now_stamp():
    return datetime.utcnow().strftime('%Y%m%d-%H%M%S')


# -----------------------------
# Folder scope checks (authoritative)
# -----------------------------
def ensure_in_ssot(file_id: str):
    """Abort 403 if target file is not directly inside the SSOT folder."""
    try:
        meta = drive_service.files().get(
            fileId=file_id,
            fields="id, parents",
            supportsAllDrives=True
        ).execute()
    except Exception:
        abort(404, description="File not found")
    parents = meta.get('parents') or []
    if FOLDER_ID not in parents:
        abort(403, description="File is not inside the SSOT folder")


# ============================================================
#        SSOT Lifecycle Folders: /ssot, /ssot/staging, /ssot/archive
# ============================================================
STAGING_FOLDER_ID = os.getenv('1cSk2p-Ds3b8OJHnVxRTMzADNXwGuaYZ8')   # /ssot/staging
ARCHIVE_FOLDER_ID = os.getenv('1_aS36KiiYb4fWkLGrFM-S8DxiHBLaY5i')   # /ssot/archive

def _ensure_subfolder(parent_id: str, name: str) -> str:
    """Find or create a subfolder under parent_id."""
    q = (
        f"'{parent_id}' in parents and "
        f"name = '{name}' and "
        f"mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    )
    res = drive_service.files().list(
        q=q, includeItemsFromAllDrives=True, supportsAllDrives=True,
        fields="files(id,name)"
    ).execute()
    if res.get('files'):
        return res['files'][0]['id']
    created = drive_service.files().create(
        body={
            'name': name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id]
        },
        fields="id",
        supportsAllDrives=True
    ).execute()
    return created['id']

# Will be populated after drive_service is ready
ALLOWED_PARENTS = set()

def init_lifecycle_folders():
    """Resolve or create /ssot/staging and /ssot/archive once drive_service is ready."""
    global STAGING_FOLDER_ID, ARCHIVE_FOLDER_ID, ALLOWED_PARENTS
    if not STAGING_FOLDER_ID:
        STAGING_FOLDER_ID = _ensure_subfolder(FOLDER_ID, 'staging')
    if not ARCHIVE_FOLDER_ID:
        ARCHIVE_FOLDER_ID = _ensure_subfolder(FOLDER_ID, 'archive')
    ALLOWED_PARENTS = {FOLDER_ID, STAGING_FOLDER_ID, ARCHIVE_FOLDER_ID}

# Initialize lifecycle folders now that drive_service is available
init_lifecycle_folders()

def _resolve_parents_arg(parents_arg):
    """
    Accepts: None | 'ssot'|'staging'|'archive' | folderId | [folderId].
    Returns: [folderId]
    """
    if not parents_arg:
        return [FOLDER_ID]
    if isinstance(parents_arg, str):
        key = parents_arg.strip().lower()
        if key in ('ssot', '/ssot'):
            return [FOLDER_ID]
        if key in ('staging', '/ssot/staging'):
            return [STAGING_FOLDER_ID]
        if key in ('archive', 'archived', '/ssot/archive'):
            return [ARCHIVE_FOLDER_ID]
        # Assume it's a folderId
        return [parents_arg]
    if isinstance(parents_arg, list) and parents_arg:
        return [parents_arg[0]]
    abort(400, description="invalid 'parents' argument")

def _enforce_allowed_parents(parents: list[str]):
    if not parents:
        abort(403, description="Missing parent folder")
    if not ALLOWED_PARENTS:
        init_lifecycle_folders()
    if parents[0] not in ALLOWED_PARENTS:
        abort(403, description="Parent folder not allowed; must be SSOT, staging, or archive.")

def _ensure_in_folder(file_id: str, folder_id: str, err="File is not in required folder"):
    meta = drive_service.files().get(
        fileId=file_id,
        fields="id,parents",
        supportsAllDrives=True
    ).execute()
    if folder_id not in (meta.get('parents') or []):
        abort(403, description=err)

def _archive_stamp():
    # Governance format: <YYYY-MM-DD-HHMM>
    return datetime.utcnow().strftime('%Y-%m-%d-%H%M')


# -----------------------------
# Lifecycle helpers
# -----------------------------
def stage_file(source_name: str, media_body):
    """Create *.proposed.<timestamp> in /ssot/staging/"""
    ts = now_stamp()
    proposed_name = f"{source_name}.proposed.{ts}"
    created = drive_service.files().create(
        body={'name': proposed_name, 'parents': [STAGING_FOLDER_ID]},
        media_body=media_body,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()
    return created

def archive_file(file_id: str) -> dict:
    """Copy current authoritative into /ssot/archive/ with timestamped name."""
    _ensure_in_folder(file_id, FOLDER_ID, err="Can only archive items from /ssot")
    meta = drive_service.files().get(
        fileId=file_id,
        fields="id,name,parents",
        supportsAllDrives=True
    ).execute()
    base, ext = os.path.splitext(meta['name'])
    stamped = f"{base}.{_archive_stamp()}{ext}"
    archived = drive_service.files().copy(
        fileId=file_id,
        body={'name': stamped, 'parents': [ARCHIVE_FOLDER_ID]},
        supportsAllDrives=True,
        fields="id,name,parents,modifiedTime,size"
    ).execute()
    return archived

def _find_staged_for(meta_name: str) -> dict | None:
    """Find a staged *.proposed.* file in /ssot/staging that matches meta_name prefix."""
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
    return max(files, key=lambda f: f.get('modifiedTime', ''), default=None) if files else None

def overwrite_file(file_id: str, media_body, new_name: str | None, staged_id: str | None):
    """
    Overwrite authoritative in /ssot with compliance:
      1) Must have a staged proposal in /ssot/staging (staged_id or discoverable).
      2) Archive the current authoritative into /ssot/archive first.
      3) Update the authoritative (exactly one current version in /ssot).
    Fails with 412 if no staged proposal is found; 500 if archive fails.
    """
    _ensure_in_folder(file_id, FOLDER_ID, err="Target is not in /ssot (authoritative)")

    meta = drive_service.files().get(
        fileId=file_id,
        fields="id,name,parents,mimeType",
        supportsAllDrives=True
    ).execute()

    staged = None
    if staged_id:
        _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId is not in /ssot/staging")
        s_meta = drive_service.files().get(
            fileId=staged_id, fields="id,name,parents", supportsAllDrives=True
        ).execute()
        if not s_meta['name'].startswith(f"{meta['name']}.proposed."):
            abort(412, description="stagedId does not match target file name")
        staged = s_meta
    else:
        staged = _find_staged_for(meta['name'])
        if not staged:
            abort(412, description="No staged proposal found in /ssot/staging for this file")

    archived = archive_file(file_id)
    if not archived or not archived.get('id'):
        abort(500, description="Archiving failed; aborting overwrite")

    body = {'name': new_name} if new_name else None
    updated = drive_service.files().update(
        fileId=file_id,
        body=body,
        media_body=media_body,
        fields="id,name,mimeType,parents,modifiedTime,size",
        supportsAllDrives=True
    ).execute()

    return {"updated": updated, "archived": archived, "usedStaged": staged}


# -----------------------------
# Routes
# -----------------------------
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
            "ssotFolderId": FOLDER_ID,
            "stagingFolderId": STAGING_FOLDER_ID,
            "archiveFolderId": ARCHIVE_FOLDER_ID
        }, 200
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500


# ---- READ ----
@app.route('/files', methods=['GET'])
@require_api_key(write=False)
def list_files():
    """List direct children of the SSOT folder (/ssot authoritative only)."""
    try:
        results = drive_service.files().list(
            q=f"'{FOLDER_ID}' in parents AND trashed = false AND mimeType != 'application/vnd.google-apps.folder'",
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
    Upload a new file.
    multipart/form-data:
      - file (binary, required)
      - name (optional)
      - parents (optional; 'ssot'|'staging'|'archive' or folderId)
      - confirm (required via guard)
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        name = request.form.get('name') or (up.filename or 'untitled')
        if not allowed_name_and_mime(name, up.mimetype):
            return jsonify({"error": "file type not allowed"}), 415

        parents_arg = request.form.get('parents')
        parents = _resolve_parents_arg(parents_arg)
        _enforce_allowed_parents(parents)

        media = MediaIoBaseUpload(
            up.stream,
            mimetype=(up.mimetype or guess_mime_from_name(name)),
            resumable=False
        )
        created = drive_service.files().create(
            body={'name': name, 'parents': parents},
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(created), 201
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
      - content (required)
      - mimeType (optional; default text/plain)
      - parents (optional; 'ssot'|'staging'|'archive' or folderId)
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
        if len(content.encode('utf-8')) > MAX_BYTES:
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


# ---- UPDATE (Binary) ----
@app.route('/files/<file_id>', methods=['PATCH'])
@require_api_key(write=True)
def update_file(file_id):
    """
    Replace contents of an existing file (binary).
    multipart/form-data:
      - file (binary, required)
      - name (optional rename; must be allowed)
      - mode (optional; 'staging'|'overwrite') — defaults to WRITE_MODE if omitted
      - stagedId (optional; required for overwrite compliance if auto-discovery fails)
      - confirm (required via guard)
    Lifecycle rules:
      - staging: write *.proposed.<ts> into /ssot/staging
      - overwrite: require a staged proposal and archive current authoritative first, then update file in /ssot
    """
    try:
        ensure_in_ssot(file_id)  # Target must be inside /ssot (authoritative)

        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        new_name = request.form.get('name')
        mode = (request.form.get('mode') or WRITE_MODE).lower()
        staged_id = request.form.get('stagedId')

        meta = drive_service.files().get(
            fileId=file_id,
            fields="id,name,parents,mimeType",
            supportsAllDrives=True
        ).execute()

        target_name = new_name or meta['name']
        target_mime = up.mimetype or guess_mime_from_name(target_name)
        if not allowed_name_and_mime(target_name, target_mime):
            return jsonify({"error": "file type not allowed"}), 415

        media = MediaIoBaseUpload(up.stream, mimetype=target_mime, resumable=False)

        if mode == 'staging':
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        # overwrite: enforce staged proposal + archive, then update
        result = overwrite_file(file_id, media, new_name, staged_id)
        return jsonify({"mode": "overwrite", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---- UPDATE (Text JSON) ----
@app.route('/files/<file_id>/text', methods=['PATCH'])
@require_api_key(write=True)
def update_text_file(file_id):
    """
    Update an existing file from JSON text content.
    JSON body:
      - content (required)
      - mimeType (optional; default text/plain)
      - name (optional rename; must be allowed; applied only at overwrite)
      - mode (optional; 'staging'|'overwrite') — defaults to WRITE_MODE if omitted
      - stagedId (optional; required for overwrite compliance if auto-discovery fails)
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
        if len(content.encode('utf-8')) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        meta = drive_service.files().get(
            fileId=file_id,
            fields="id,name,parents,mimeType",
            supportsAllDrives=True
        ).execute()

        target_name = new_name or meta['name']
        if not allowed_name_and_mime(target_name, mime):
            return jsonify({"error": "file type not allowed"}), 415

        media = text_upload_media(content, mime)

        if mode == 'staging':
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        # overwrite: enforce staged proposal + archive, then update
        result = overwrite_file(file_id, media, new_name, staged_id)
        return jsonify({"mode": "overwrite", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---- METADATA ONLY (Rename) ----
@app.route('/files/<file_id>/metadata', methods=['PATCH'])
@require_api_key(write=True)
def rename_file(file_id):
    """Rename without changing content (must remain inside /ssot)."""
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


# ---- STAGING CLEANUP (scoped to /ssot/staging only) ----
@app.route('/staging/cleanup', methods=['POST'])
@require_api_key(write=True)
def cleanup_staging():
    """
    Deletes ALL files inside /ssot/staging (not folders),
    leaving /ssot and /ssot/archive untouched.
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


# -----------------------------
# Entrypoint
# -----------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
