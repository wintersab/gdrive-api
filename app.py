from flask import Flask, jsonify, send_file, request
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from functools import wraps
from datetime import datetime
import io, os

app = Flask(__name__)

# ======= CONFIG =======
FOLDER_ID = '1Ox7DXcd9AEvF84FkCVyB90MGHR0v7q7R'

SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'

# Guardrails / ops controls (set in Render Environment)
API_KEY = os.getenv('API_KEY')                           # single key for GPT
READ_ONLY = os.getenv('READ_ONLY', 'true').lower() == 'true'
WRITE_CONFIRM_PHRASE = os.getenv('WRITE_CONFIRM_PHRASE') # required for writes
WRITE_MODE = os.getenv('WRITE_MODE', 'staging').lower()  # 'staging' or 'overwrite'

# ======= AUTH =======
def require_api_key(write=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Key check for all requests
            provided = request.headers.get('X-API-Key')
            if not API_KEY or not provided or provided != API_KEY:
                return jsonify({'error': 'unauthorized'}), 401

            # Extra checks for write requests
            if write:
                if READ_ONLY:
                    return jsonify({'error': 'read-only mode: writes are disabled'}), 403
                # Require explicit human confirmation
                confirm = (
                    request.form.get('confirm')
                    or request.headers.get('X-Write-Confirm')
                    or (request.json or {}).get('confirm') if request.is_json else None
                )
                if not WRITE_CONFIRM_PHRASE or confirm != WRITE_CONFIRM_PHRASE:
                    return jsonify({'error': 'missing or invalid confirmation phrase'}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ======= DRIVE CLIENT =======
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
drive_service = build('drive', 'v3', credentials=credentials)

# ======= ROUTES =======
@app.route('/', methods=['GET'])
def index():
    return "GDrive SSOT API is running. Try /healthz and /files", 200

@app.route('/healthz', methods=['GET'])
@require_api_key(write=False)
def healthz():
    try:
        about = drive_service.about().get(fields="user(emailAddress)").execute()
        return {"status": "ok", "as": about.get("user", {}).get("emailAddress")}, 200
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500

# ---- READ ----
@app.route('/files', methods=['GET'])
@require_api_key(write=False)
def list_files():
    """List direct children of the SSOT folder."""
    try:
        results = drive_service.files().list(
            q=f"'{FOLDER_ID}' in parents and trashed = false",
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            fields="files(id,name,mimeType,parents,modifiedTime,size)"
        ).execute()
        files = results.get('files', [])
        return jsonify(files), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>/content', methods=['GET'])
@require_api_key(write=False)
def get_file_content(file_id):
    """Download file bytes; supports Shared drives."""
    try:
        request_file = drive_service.files().get_media(
            fileId=file_id, supportsAllDrives=True
        )
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_file)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        fh.seek(0)
        return send_file(fh, as_attachment=False, download_name="file")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- WRITE ----
@app.route('/files', methods=['POST'])
@require_api_key(write=True)
def upload_file():
    """
    Upload a new file into the SSOT folder.
    multipart/form-data:
      - file (binary, required)
      - name (optional)
      - confirm (string, must match WRITE_CONFIRM_PHRASE)
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400

        up = request.files['file']
        name = request.form.get('name') or (up.filename or 'untitled')

        media = MediaIoBaseUpload(up.stream, mimetype=up.mimetype or 'application/octet-stream', resumable=False)
        metadata = {'name': name, 'parents': [FOLDER_ID]}

        created = drive_service.files().create(
            body=metadata,
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(created), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>', methods=['PATCH'])
@require_api_key(write=True)
def update_file(file_id):
    """
    Replace contents of an existing file.
    multipart/form-data:
      - file (binary, required)
      - name (optional rename)
      - confirm (string, must match WRITE_CONFIRM_PHRASE)
    Staging mode: creates a proposed copy instead of overwriting.
    Overwrite mode: first creates a backup copy, then updates.
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file'"}), 400

        # Get current metadata
        meta = drive_service.files().get(
            fileId=file_id,
            fields="id,name,parents,mimeType",
            supportsAllDrives=True
        ).execute()

        up = request.files['file']
        new_name = request.form.get('name')
        now = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

        # If staging: create a proposed sibling file (do not modify original)
        if WRITE_MODE == 'staging':
            proposed_name = f"{meta['name']}.proposed.{now}"
            media = MediaIoBaseUpload(up.stream, mimetype=up.mimetype or 'application/octet-stream', resumable=False)
            created = drive_service.files().create(
                body={'name': proposed_name, 'parents': meta.get('parents', [FOLDER_ID])},
                media_body=media,
                fields="id,name,mimeType,parents,modifiedTime,size",
                supportsAllDrives=True
            ).execute()
            return jsonify({"mode": "staging", "created": created, "sourceId": file_id}), 201

        # Else overwrite: first make a backup copy
        backup_name = f"{meta['name']}.backup.{now}"
        drive_service.files().copy(
            fileId=file_id,
            body={'name': backup_name, 'parents': meta.get('parents', [FOLDER_ID])},
            supportsAllDrives=True,
            fields="id"
        ).execute()

        media = MediaIoBaseUpload(up.stream, mimetype=up.mimetype or 'application/octet-stream', resumable=False)
        body = {}
        if new_name:
            body['name'] = new_name

        updated = drive_service.files().update(
            fileId=file_id,
            body=body if body else None,
            media_body=media,
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()

        return jsonify({"mode": "overwrite", "updated": updated, "backupOf": backup_name}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>/metadata', methods=['PATCH'])
@require_api_key(write=True)
def rename_file(file_id):
    """
    Rename without changing content.
    JSON body:
      - name (required)
      - confirm (string, must match WRITE_CONFIRM_PHRASE)
    """
    try:
        data = request.get_json(silent=True) or {}
        if data.get('confirm') != WRITE_CONFIRM_PHRASE:
            return jsonify({"error": "missing or invalid confirmation phrase"}), 403
        new_name = data.get('name')
        if not new_name:
            return jsonify({"error": "missing 'name'"}), 400

        updated = drive_service.files().update(
            fileId=file_id,
            body={'name': new_name},
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(updated), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Debug: folder meta (shows driveId if Shared drive)
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
