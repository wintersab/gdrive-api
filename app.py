from flask import Flask, jsonify, send_file, request, abort
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import io

app = Flask(__name__)

# ✅ Your SSOT folder (Shared drive)
FOLDER_ID = '1Ox7DXcd9AEvF84FkCVyB90MGHR0v7q7R'

# Google Drive API setup
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
drive_service = build('drive', 'v3', credentials=credentials)

@app.route('/', methods=['GET'])
def index():
    return "GDrive SSOT API is running. Try /healthz and /files", 200

@app.route('/healthz', methods=['GET'])
def healthz():
    try:
        about = drive_service.about().get(fields="user(emailAddress)").execute()
        return {"status": "ok", "as": about.get("user", {}).get("emailAddress")}, 200
    except Exception as e:
        return {"status": "error", "error": str(e)}, 500

# ---- READ: list & download ----------------------------------------------------

@app.route('/files', methods=['GET'])
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
        print("DEBUG /files -> count:", len(files))
        return jsonify(files), 200
    except Exception as e:
        print("ERROR /files:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>/content', methods=['GET'])
def get_file_content(file_id):
    """Download file bytes; supports Shared drives."""
    try:
        request_file = drive_service.files().get_media(
            fileId=file_id,
            supportsAllDrives=True
        )
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_file)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        fh.seek(0)
        return send_file(fh, as_attachment=False, download_name="file")
    except Exception as e:
        print("ERROR /files/<id>/content:", e)
        return jsonify({"error": str(e)}), 500

# ---- WRITE: upload new & update existing -------------------------------------

@app.route('/files', methods=['POST'])
def upload_file():
    """
    Upload a new file into the SSOT folder.
    Accepts multipart/form-data with:
      - file: binary file (required)
      - name: optional override filename
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file' field"}), 400

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
        print("ERROR POST /files:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>', methods=['PATCH'])
def update_file(file_id):
    """
    Replace the contents of an existing file.
    Accepts multipart/form-data with:
      - file: binary file (required)
      - name: optional new name (rename)
    NOTE: This updates binary files (txt, md, yml, csv, docx). It does NOT
          convert native Google Docs; for those, upload a new binary or use export.
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "missing 'file' field"}), 400

        up = request.files['file']
        new_name = request.form.get('name')

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

        return jsonify(updated), 200
    except Exception as e:
        print("ERROR PATCH /files/<id>:", e)
        return jsonify({"error": str(e)}), 500

# Optional: rename without changing content
@app.route('/files/<file_id>/metadata', methods=['PATCH'])
def rename_file(file_id):
    try:
        data = request.get_json(silent=True) or {}
        new_name = data.get('name')
        if not new_name:
            return jsonify({"error": "missing 'name' in JSON body"}), 400
        updated = drive_service.files().update(
            fileId=file_id,
            body={'name': new_name},
            fields="id,name,mimeType,parents,modifiedTime,size",
            supportsAllDrives=True
        ).execute()
        return jsonify(updated), 200
    except Exception as e:
        print("ERROR PATCH /files/<id>/metadata:", e)
        return jsonify({"error": str(e)}), 500

# Helpful: confirm folder meta (should show a driveId if Shared drive)
@app.route('/debug/folder', methods=['GET'])
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
