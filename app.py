from flask import Flask, jsonify, send_file, request, abort
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from functools import wraps
from datetime import datetime
import io, os, mimetypes, json, re, hashlib

# Optional YAML validation (best-effort)
try:
    import yaml
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

app = Flask(__name__)

# ======= SSOT CONFIG (Shared Drive) =======
FOLDER_ID = os.getenv('FOLDER_ID') or '1Ox7DXcd9AEvF84FkCVyB90MGHR0v7q7R'  # /ssot (authoritative)
if not FOLDER_ID:
    raise RuntimeError("FOLDER_ID env var is required (Google Drive folder id for /ssot)")

# ======= Google Drive API =======
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
drive_service = build('drive', 'v3', credentials=credentials)

# ======= Guardrails / Ops Controls =======
API_KEY = os.getenv('API_KEY')  # required for all routes
READ_ONLY = os.getenv('READ_ONLY', 'true').lower() == 'true'
WRITE_CONFIRM_PHRASE = os.getenv('WRITE_CONFIRM_PHRASE')
WRITE_MODE = os.getenv('WRITE_MODE', 'staging').lower()  # default; can be overridden per-request
MAX_BYTES = int(os.getenv('MAX_BYTES', '2000000'))
app.config['MAX_CONTENT_LENGTH'] = MAX_BYTES

# ======= Allowed types & canonical MIME mapping =======
ALLOWED_EXTS = {'.txt', '.md', '.markdown', '.yml', '.yaml', '.json', '.csv', '.docx'}
ALLOWED_MIMES = {
    'text/plain', 'text/markdown', 'text/x-markdown',
    'application/x-yaml', 'text/yaml',
    'application/json', 'text/csv',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
}
CANONICAL_MIME = {
    '.yml': 'application/x-yaml',
    '.yaml': 'application/x-yaml',
    '.json': 'application/json',
    '.csv': 'text/csv',
    '.md': 'text/markdown',
    '.markdown': 'text/markdown',
    '.txt': 'text/plain',
}
mimetypes.init()

def _ext(name): return os.path.splitext(name or '')[1].lower()
def guess_mime_from_name(name: str) -> str:
    mime, _ = mimetypes.guess_type(name)
    return mime or 'application/octet-stream'
def canonical_mime_for(name: str, fallback=None) -> str:
    return CANONICAL_MIME.get(_ext(name)) or (fallback or guess_mime_from_name(name))

# ======= Subfolders (/ssot/staging, /ssot/archive) =======
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

STAGING_FOLDER_ID = os.getenv('STAGING_FOLDER_ID') or _ensure_subfolder(FOLDER_ID, 'staging')
ARCHIVE_FOLDER_ID = os.getenv('ARCHIVE_FOLDER_ID') or _ensure_subfolder(FOLDER_ID, 'archive')
ALLOWED_PARENTS = {FOLDER_ID, STAGING_FOLDER_ID, ARCHIVE_FOLDER_ID}

# ======= Drive helpers =======
def _get_drive_id(folder_id: str):
    try:
        meta = drive_service.files().get(
            fileId=folder_id,
            fields="id, driveId",
            supportsAllDrives=True
        ).execute()
        return meta.get('driveId')
    except Exception:
        return None

def _download_bytes(file_id: str) -> bytes:
    req = drive_service.files().get_media(fileId=file_id, supportsAllDrives=True)
    buf = io.BytesIO()
    downloader = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return buf.getvalue()

def _md5_hex(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()

def _strip_outer_quotes(s: str) -> str:
    if not isinstance(s, str) or len(s) < 2:
        return s
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s

def _extract_parents_from_request():
    """
    Returns a single token: alias (ssot/staging/archive) or folderId,
    normalized from query or body, in any common shape.
    """
    # 1) Query first (covers ?parents=ssot, repeated, JSON-in-string, etc.)
    raw = request.args.getlist('parents') or request.args.get('parents')
    if not raw:
        # 2) Some runtimes send JSON bodies on GET; try both Flask and manual parse
        body = None
        try:
            body = request.get_json(silent=True)
        except Exception:
            body = None
        if body is None and request.data:
            try:
                body = json.loads(request.data.decode('utf-8'))
            except Exception:
                body = None
        if isinstance(body, dict) and 'parents' in body:
            raw = body['parents']

    # 3) Accept dict shapes: {"alias":"staging"} or {"id":"<folderId>"}, etc.
    if isinstance(raw, dict):
        for key in ('alias', 'value', 'id', 'folderId', 'name'):
            if raw.get(key):
                raw = raw[key]
                break

    # 4) Normalize JSON-array-in-a-string: '["ssot"]'
    if isinstance(raw, str) and raw.strip().startswith('[') and raw.strip().endswith(']'):
        try:
            arr = json.loads(raw)
            if isinstance(arr, list) and arr:
                raw = arr
        except Exception:
            pass

    # 5) If list, take first; if string, strip outer quotes; else None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, str):
        raw = _strip_outer_quotes(raw.strip())
        return raw or None
    return raw if isinstance(raw, str) else None

# ======= Param normalization (fix for parents regression) =======
def _coerce_parents_param(param):
    """
    Accepts:
      - None
      - 'ssot' | 'staging' | 'archive' | <folderId>
      - ['ssot'] (true array)
      - '["ssot"]' (JSON array encoded as string)
      - repeated query (?parents=ssot&parents=staging) -> first wins
    Returns a string or list[str] suitable for _resolve_parents_arg.
    """
    if param is None:
        return None
    # Already a list (from getlist or JSON)
    if isinstance(param, list):
        if not param:
            return None
        first = param[0]
        if isinstance(first, str):
            s = first.strip()
            if s.startswith('[') and s.endswith(']'):
                try:
                    arr = json.loads(s)
                    if isinstance(arr, list) and arr:
                        return arr
                except Exception:
                    pass
        return param
    # A single string (possibly JSON array-as-string)
    if isinstance(param, str):
        s = param.strip()
        if s.startswith('[') and s.endswith(']'):
            try:
                arr = json.loads(s)
                if isinstance(arr, list) and arr:
                    return arr
            except Exception:
                pass
        return s
    return param

# ======= Parent resolution & folder guards =======
def _resolve_parents_arg(parents_arg):
    """
    Accepts None, alias, folderId, or [alias]/[folderId].
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
        return token  # assume Drive folderId

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

def ensure_in_ssot(file_id: str):
    try:
        meta = drive_service.files().get(
            fileId=file_id, fields="id, parents", supportsAllDrives=True
        ).execute()
    except Exception:
        abort(404, description="File not found")
    if FOLDER_ID not in (meta.get('parents') or []):
        abort(403, description="File is not inside the SSOT folder")

# ======= Staging "complete document" validator =======
CONFLICT_MARKERS = ('<<<<<<<', '=======', '>>>>>>>')
PATCH_MARKERS_RE = re.compile(r'^(diff --git|Index: |\*\*\* |--- [ab]/|\+\+\+ [ab]/|@@ )', re.MULTILINE)

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
    lines = [ln for ln in text.splitlines()[:200]]
    plus_minus = sum(1 for ln in lines if (ln.startswith('+') or (ln.startswith('-') and not ln.startswith('- '))))
    return (plus_minus >= max(5, int(0.3 * (len(lines) or 1))))

def _validate_full_document_for_staging(name: str, mime: str, content_bytes: bytes):
    if not content_bytes or len(content_bytes) == 0:
        abort(422, description="stagingRequiresFullDocument: empty content not allowed")
    if not _is_texty(mime, name):
        return
    try:
        text = content_bytes.decode('utf-8', errors='replace')
    except Exception:
        abort(422, description="stagingRequiresFullDocument: content must be UTF-8 text for text formats")
    if _looks_like_patch_or_diff(text):
        abort(422, description="stagingRequiresFullDocument: detected diff/patch/fragment; submit a full file")

    ext = _ext(name)
    if ext in ('.yml', '.yaml'):
        if HAVE_YAML:
            try:
                parsed = yaml.safe_load(text)
            except Exception:
                abort(422, description="stagingRequiresFullDocument: invalid YAML; submit well-formed YAML")
            if parsed is None:
                abort(422, description="stagingRequiresFullDocument: YAML is empty; submit complete document")
    elif ext == '.json':
        try:
            json.loads(text)
        except Exception:
            abort(422, description="stagingRequiresFullDocument: invalid JSON; submit full JSON document")
    elif ext == '.csv':
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines or (len(lines) == 1 and (',' not in lines[0] and '\t' not in lines[0])):
            abort(422, description="stagingRequiresFullDocument: CSV appears incomplete; submit full table")

# ======= Auth wrapper =======
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

# ======= Lifecycle helpers: stage → archive → overwrite/promote =======
def now_stamp():
    return datetime.utcnow().strftime('%Y%m%d-%H%M%S')
def _archive_stamp():
    return datetime.utcnow().strftime('%Y-%m-%d-%H%M')

def stage_file(source_name: str, media_body):
    proposed_name = f"{source_name}.proposed.{now_stamp()}"
    created = drive_service.files().create(
        body={'name': proposed_name, 'parents': [STAGING_FOLDER_ID]},
        media_body=media_body,
        fields="id,name,mimeType,parents,modifiedTime,size,md5Checksum",
        supportsAllDrives=True
    ).execute()
    return created

def archive_file(file_id: str) -> dict:
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
        fields="id,name,parents,modifiedTime,size,md5Checksum"
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
        fields="files(id,name,modifiedTime,size,md5Checksum,mimeType)"
    ).execute()
    files = res.get('files', [])
    if not files:
        return None
    return max(files, key=lambda f: f.get('modifiedTime', ''))

def _update_bytes_with_mime(file_id: str, content_bytes: bytes, name_for_mime: str, prefer_mime=None):
    mime = canonical_mime_for(name_for_mime, prefer_mime)
    media = MediaIoBaseUpload(io.BytesIO(content_bytes), mimetype=mime, resumable=False)
    updated = drive_service.files().update(
        fileId=file_id, body=None, media_body=media,
        fields="id,name,mimeType,parents,modifiedTime,size,md5Checksum",
        supportsAllDrives=True
    ).execute()
    return updated

def overwrite_file(file_id: str, content_bytes: bytes, target_name: str, prefer_mime=None, staged_id=None):
    _ensure_in_folder(file_id, FOLDER_ID, err="Target is not in /ssot (authoritative)")

    staged_meta = None
    if staged_id:
        _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId is not in /ssot/staging")
        staged_meta = drive_service.files().get(
            fileId=staged_id, fields="id,name,parents", supportsAllDrives=True
        ).execute()
        if not staged_meta['name'].startswith(f"{target_name}.proposed."):
            abort(412, description="stagedId does not match target file name")
    else:
        staged_meta = _find_staged_for(target_name)
        if not staged_meta:
            abort(412, description="No staged proposal found in /ssot/staging for this file")

    archived = archive_file(file_id)
    if not archived or not archived.get('id'):
        abort(500, description="Archiving failed; aborting overwrite")

    updated = _update_bytes_with_mime(file_id, content_bytes, target_name, prefer_mime)
    return {"updated": updated, "archived": archived, "usedStaged": staged_meta}

def promote_staged_to_authoritative(authoritative_id: str, staged_id: str) -> dict:
    _ensure_in_folder(authoritative_id, FOLDER_ID, err="authoritativeId must be inside /ssot")
    _ensure_in_folder(staged_id, STAGING_FOLDER_ID, err="stagedId must be inside /ssot/staging")

    auth_before = drive_service.files().get(
        fileId=authoritative_id, fields="id,name,parents,mimeType,modifiedTime,size,md5Checksum",
        supportsAllDrives=True
    ).execute()
    staged_meta = drive_service.files().get(
        fileId=staged_id, fields="id,name,parents,mimeType,modifiedTime,size,md5Checksum",
        supportsAllDrives=True
    ).execute()

    auth_name = auth_before.get('name') or ''
    staged_bytes = _download_bytes(staged_id)
    staged_md5 = _md5_hex(staged_bytes)

    _validate_full_document_for_staging(
        staged_meta.get('name') or auth_name,
        staged_meta.get('mimeType') or canonical_mime_for(staged_meta.get('name') or auth_name),
        staged_bytes
    )

    archived = archive_file(authoritative_id)

    canonical_for_auth = canonical_mime_for(auth_name, staged_meta.get('mimeType'))
    updated = _update_bytes_with_mime(authoritative_id, staged_bytes, auth_name, canonical_for_auth)

    needs_retry = False
    if updated.get('md5Checksum') and updated['md5Checksum'] != staged_md5:
        needs_retry = True
        app.logger.warning(f"[promote] checksum mismatch (auth {updated.get('md5Checksum')} vs staged {staged_md5})")
    if updated.get('mimeType') != canonical_for_auth:
        needs_retry = True
        app.logger.warning(f"[promote] MIME mismatch (auth {updated.get('mimeType')} vs canonical {canonical_for_auth})")

    if needs_retry:
        updated = _update_bytes_with_mime(authoritative_id, staged_bytes, auth_name, canonical_for_auth)
        updated = drive_service.files().get(
            fileId=authoritative_id, fields="id,name,parents,mimeType,modifiedTime,size,md5Checksum",
            supportsAllDrives=True
        ).execute()
        if (updated.get('md5Checksum') and updated['md5Checksum'] != staged_md5) or (updated.get('mimeType') != canonical_for_auth):
            abort(500, description="mimeOrChecksumMismatch: promotion failed to achieve canonical MIME and checksum")

    app.logger.info(f"[promote] finalized {auth_name}: mime={updated.get('mimeType')} md5={updated.get('md5Checksum')}")

    return {
        "actions": ["archived", "promoted", "finalized"],
        "authoritativeBefore": auth_before,
        "archived": archived,
        "staged": staged_meta,
        "authoritativeAfter": updated
    }

# ======= Error normalization =======
@app.errorhandler(422)
def handle_422(e):
    return jsonify({"error": getattr(e, "description", "Unprocessable Entity")}), 422

# ======= Routes =======
@app.route('/', methods=['GET'])
def index():
    return "GDrive SSOT API is running. Try /healthz and /files", 200

@app.route('/healthz', methods=['GET'])
@require_api_key(write=False)
def healthz():
    try:
        about = drive_service.about().get(fields="user(emailAddress)").execute()
        drive_id = _get_drive_id(FOLDER_ID)
        return {
            "status": "ok",
            "as": about.get("user", {}).get("emailAddress"),
            "readOnly": READ_ONLY,
            "writeMode": WRITE_MODE,
            "maxBytes": MAX_BYTES,
            "authoritativeFolderId": FOLDER_ID,
            "stagingFolderId": STAGING_FOLDER_ID,
            "archiveFolderId": ARCHIVE_FOLDER_ID,
            "driveId": drive_id,
            "aliases": {
                "ssot": FOLDER_ID,
                "staging": STAGING_FOLDER_ID,
                "archive": ARCHIVE_FOLDER_ID
            }
        }, 200
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500

# ---- LIST (alias-aware; robust param normalization + Shared Drive safe) ----
@app.route('/files', methods=['GET'])
@require_api_key(write=False)
def list_files():
    try:
        token = _extract_parents_from_request()  # accepts alias/folderId in any shape
        folder_id = _resolve_parents_arg(token)[0] if token else FOLDER_ID

        q = f"'{folder_id}' in parents and trashed=false"
        fields = "files(id,name,mimeType,parents,modifiedTime,size,md5Checksum)"

        # Try Shared Drive-scoped query first
        files = []
        drive_id = _get_drive_id(folder_id)
        try:
            params = dict(
                q=q,
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
                fields=fields
            )
            if drive_id:
                params.update(corpora="drive", driveId=drive_id)
            else:
                params.update(corpora="allDrives")
            files = drive_service.files().list(**params).execute().get('files', [])
        except Exception:
            # Fallback: drop corpora/driveId if Drive is fussy
            files = drive_service.files().list(
                q=q,
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
                fields=fields
            ).execute().get('files', [])

        return jsonify(files), 200
    except Exception as e:
        return jsonify({
            "error": str(e),
            "hint": "parents accepted as ssot|staging|archive or folderId; also [\"ssot\"] or JSON body."
        }), 500

# ---- READ: bytes + text ----
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

# ---- CREATE (binary) ----
@app.route('/files', methods=['POST'])
@require_api_key(write=True)
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        raw = up.read()
        name = request.form.get('name') or (up.filename or 'untitled')
        mime = up.mimetype or guess_mime_from_name(name)

        if _ext(name) not in ALLOWED_EXTS:
            return jsonify({"error": "file type not allowed"}), 415
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        parents_raw = request.form.getlist('parents') or request.form.get('parents')
        parents = _resolve_parents_arg(_coerce_parents_param(parents_raw))
        _enforce_allowed_parents(parents)

        if parents[0] == STAGING_FOLDER_ID:
            mime = canonical_mime_for(name, mime)
            _validate_full_document_for_staging(name, mime, raw)

        media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)
        created = drive_service.files().create(
            body={'name': name, 'parents': parents},
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size,md5Checksum",
            supportsAllDrives=True
        ).execute()
        return jsonify(created), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- UPDATE (binary) ----
@app.route('/files/<file_id>', methods=['PATCH'])
@require_api_key(write=True)
def update_file(file_id):
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

        if _ext(target_name) not in ALLOWED_EXTS:
            return jsonify({"error": "file type not allowed"}), 415
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        if mode == 'staging':
            mime = canonical_mime_for(target_name, mime)
            _validate_full_document_for_staging(target_name, mime, raw)
            media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        result = overwrite_file(file_id, raw, target_name, mime, staged_id)
        return jsonify({"mode": "overwrite", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- CREATE (text/json) ----
@app.route('/files/text', methods=['POST'])
@require_api_key(write=True)
def create_text_file():
    try:
        data = request.get_json(silent=True) or {}
        name = data.get('name')
        content = data.get('content')
        mime = data.get('mimeType') or 'text/plain'
        parents_arg = data.get('parents')
        if not name or content is None:
            return jsonify({"error": "missing 'name' or 'content'"}), 400
        if _ext(name) not in ALLOWED_EXTS:
            return jsonify({"error": "file type not allowed"}), 415
        raw = (content or '').encode('utf-8')
        if len(raw) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        parents = _resolve_parents_arg(_coerce_parents_param(parents_arg))
        _enforce_allowed_parents(parents)

        if parents[0] == STAGING_FOLDER_ID:
            mime = canonical_mime_for(name, mime)
            _validate_full_document_for_staging(name, mime, raw)

        media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)
        created = drive_service.files().create(
            body={'name': name, 'parents': parents},
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size,md5Checksum",
            supportsAllDrives=True
        ).execute()
        return jsonify(created), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- UPDATE (text/json) ----
@app.route('/files/<file_id>/text', methods=['PATCH'])
@require_api_key(write=True)
def update_text_file(file_id):
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
        if _ext(target_name) not in ALLOWED_EXTS:
            return jsonify({"error": "file type not allowed"}), 415

        if mode == 'staging':
            mime = canonical_mime_for(target_name, mime)
            _validate_full_document_for_staging(target_name, mime, raw)
            media = MediaIoBaseUpload(io.BytesIO(raw), mimetype=mime, resumable=False)
            created = stage_file(meta['name'], media)
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        result = overwrite_file(file_id, raw, target_name, mime, staged_id)
        return jsonify({"mode": "overwrite", **result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- METADATA ONLY (rename) ----
@app.route('/files/<file_id>/metadata', methods=['PATCH'])
@require_api_key(write=True)
def rename_file(file_id):
    try:
        ensure_in_ssot(file_id)
        data = request.get_json(silent=True) or {}
        new_name = data.get('name')
        if not new_name:
            return jsonify({"error": "missing 'name'"}), 400
        if _ext(new_name) not in ALLOWED_EXTS:
            return jsonify({"error": "file type not allowed"}), 415

        updated = drive_service.files().update(
            fileId=file_id,
            body={'name': new_name},
            fields="id,name,mimeType,parents,modifiedTime,size,md5Checksum",
            supportsAllDrives=True
        ).execute()
        return jsonify(updated), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- STAGING CLEANUP ----
@app.route('/staging/cleanup', methods=['POST'])
@require_api_key(write=True)
def cleanup_staging():
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

# ---- PROMOTE (archive → promote by BYTES) ----
@app.route('/promote', methods=['POST'])
@require_api_key(write=True)
def promote():
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
