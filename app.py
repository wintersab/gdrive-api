from flask import Flask, jsonify, send_file
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io

app = Flask(__name__)

# ✅ Your new SSOT folder (Shared drive)
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

@app.route('/files', methods=['GET'])
def list_files():
    """
    Lists files directly under the SSOT folder.
    Includes Shared drive flags so it can see content in Shared drives.
    """
    try:
        results = drive_service.files().list(
            q=f"'{FOLDER_ID}' in parents and trashed = false",
            includeItemsFromAllDrives=True,
            supportsAllDrives=True,
            fields="files(id,name,mimeType,parents)"
        ).execute()
        files = results.get('files', [])
        print("DEBUG /files -> count:", len(files))
        return jsonify(files), 200
    except Exception as e:
        print("ERROR /files:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/files/<file_id>/content', methods=['GET'])
def get_file_content(file_id):
    """Downloads file bytes; also supports Shared drives."""
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

# Helpful debug: shows if the folder is recognized and has a driveId (Shared drive)
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
