from flask import Flask, jsonify, request, send_file
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io

app = Flask(__name__)

# Replace with your actual folder ID
FOLDER_ID = '1SN-F1-w7Ku551BRiSzw6f0l43HB4Lb_5'

# Load credentials from service account
SCOPES = ['https://www.googleapis.com/auth/drive']
SERVICE_ACCOUNT_FILE = 'service-account.json'
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
drive_service = build('drive', 'v3', credentials=credentials)

@app.route('/files', methods=['GET'])
def list_files():
    query = f"'{FOLDER_ID}' in parents"
    results = drive_service.files().list(q=query, fields="files(id, name, mimeType)").execute()
    return jsonify(results['files'])

@app.route('/files/<file_id>/content', methods=['GET'])
def get_file_content(file_id):
    request_file = drive_service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request_file)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    fh.seek(0)
    return send_file(fh, as_attachment=False, download_name="file")

# Later: add upload or update endpoints here

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
