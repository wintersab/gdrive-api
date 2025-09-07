from flask import Flask, jsonify, send_file, request, abort
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from functools import wraps
from datetime import datetime
import io, os, mimetypes

app = Flask(__name__)

# ======= SSOT CONFIG (Folder lives in a Shared drive) =======
FOLDER_ID = '1Ox7DXcd9AEvF84FkCVyB90MGHR0v7q7R'  # <— your SSOT folder ID

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
WRITE_MODE = os.getenv('WRITE_MODE', 'staging').lower()  # 'staging' or 'overwrite'

# Max request body size (default 2MB). Flask will reject larger requests (413).
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
                # confirmation phrase from JSON, form, or header
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


def allowed_name_and_mime(name: str, mime: str | None) -> bool:
    ext = os.path.splitext(name or '')[1].lower()
    if ext not in ALLOWED_EXTS:
        return False
    # If mime is missing, infer from name
    mime = mime or guess_mime_from_name(name)
    # Some md/yaml often show as text/plain; allow if ext is whitelisted
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
            fileId=file_id,
            fields="id, parents",
            supportsAllDrives=True
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
            "maxBytes": MAX_BYTES
        }, 200
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500


# ---- READ ----
@app.route('/files', methods=['GET'])
@require_api_key(write=False)
def list_files():
    """List direct children of the SSOT folder."""
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
    Upload a new file into the SSOT folder.
    multipart/form-data:
      - file (binary, required)
      - name (optional)
      - confirm (required via guard)
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        name = request.form.get('name') or (up.filename or 'untitled')
        if not allowed_name_and_mime(name, up.mimetype):
            return jsonify({"error": "file type not allowed"}), 415

        media = MediaIoBaseUpload(
            up.stream,
            mimetype=(up.mimetype or guess_mime_from_name(name)),
            resumable=False
        )
        created = drive_service.files().create(
            body={'name': name, 'parents': [FOLDER_ID]},
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
      - confirm (required via guard)
    WRITE_MODE:
      - 'staging': creates a .proposed.TIMESTAMP copy (original untouched)
      - 'overwrite': creates a .backup.TIMESTAMP, then updates original
    """
    try:
        ensure_in_ssot(file_id)

        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400
        up = request.files['file']
        new_name = request.form.get('name')

        # Current meta
        meta = drive_service.files().get(
            fileId=file_id,
            fields="id,name,parents,mimeType",
            supportsAllDrives=True
        ).execute()

        # Enforce type allowlist (based on new name if provided else existing name)
        target_name = new_name or meta['name']
        target_mime = up.mimetype or guess_mime_from_name(target_name)
        if not allowed_name_and_mime(target_name, target_mime):
            return jsonify({"error": "file type not allowed"}), 415

        ts = now_stamp()

        if WRITE_MODE == 'staging':
            proposed_name = f"{meta['name']}.proposed.{ts}"
            media = MediaIoBaseUpload(up.stream, mimetype=target_mime, resumable=False)
            created = drive_service.files().create(
                body={'name': proposed_name, 'parents': meta.get('parents', [FOLDER_ID])},
                media_body=media,
                fields="id,name,mimeType,parents,modifiedTime,size",
                supportsAllDrives=True
            ).execute()
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        # overwrite: backup then update
        backup_name = f"{meta['name']}.backup.{ts}"
        drive_service.files().copy(
            fileId=file_id,
            body={'name': backup_name, 'parents': meta.get('parents', [FOLDER_ID])},
            supportsAllDrives=True,
            fields="id"
        ).execute()

        media = MediaIoBaseUpload(up.stream, mimetype=target_mime, resumable=False)
        body = {'name': new_name} if new_name else None
        updated = drive_service.files().update(
            fileId=file_id,
            body=body,
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify({"mode": "overwrite", "updated": updated, "backupOf": backup_name}), 200

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
      - confirm (required via guard)
    """
    try:
        data = request.get_json(silent=True) or {}
        name = data.get('name')
        content = data.get('content')
        mime = data.get('mimeType') or 'text/plain'
        if not name or content is None:
            return jsonify({"error": "missing 'name' or 'content'"}), 400
        if not allowed_name_and_mime(name, mime):
            return jsonify({"error": "file type not allowed"}), 415
        if len(content.encode('utf-8')) > MAX_BYTES:
            return jsonify({"error": "content exceeds MAX_BYTES"}), 413

        media = text_upload_media(content, mime)
        created = drive_service.files().create(
            body={'name': name, 'parents': [FOLDER_ID]},
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
    Update an existing file from JSON text content.
    JSON body:
      - content (required)
      - mimeType (optional; default text/plain)
      - name (optional rename; must be allowed; only applied in overwrite mode)
      - confirm (required via guard)
    Honors WRITE_MODE (staging/overwrite) with backups.
    """
    try:
        ensure_in_ssot(file_id)

        data = request.get_json(silent=True) or {}
        content = data.get('content')
        mime = data.get('mimeType') or 'text/plain'
        new_name = data.get('name')
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

        ts = now_stamp()

        if WRITE_MODE == 'staging':
            proposed_name = f"{meta['name']}.proposed.{ts}"
            media = text_upload_media(content, mime)
            created = drive_service.files().create(
                body={'name': proposed_name, 'parents': meta.get('parents', [FOLDER_ID])},
                media_body=media,
                fields="id,name,mimeType,parents,modifiedTime,size",
                supportsAllDrives=True
            ).execute()
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        # overwrite
        backup_name = f"{meta['name']}.backup.{ts}"
        drive_service.files().copy(
            fileId=file_id,
            body={'name': backup_name, 'parents': meta.get('parents', [FOLDER_ID])},
            supportsAllDrives=True,
            fields="id"
        ).execute()

        body = {'name': new_name} if new_name else None
        media = text_upload_media(content, mime)
        updated = drive_service.files().update(
            fileId=file_id,
            body=body,
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify({"mode": "overwrite", "updated": updated, "backupOf": backup_name}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---- METADATA ONLY (Rename) ----
@app.route('/files/<file_id>/metadata', methods=['PATCH'])
@require_api_key(write=True)
def rename_file(file_id):
    """Rename without changing content (still requires confirm; must stay inside SSOT)."""
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
    app.run(host='0.0.0.0', port=8080)
