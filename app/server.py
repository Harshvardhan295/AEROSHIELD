import os
import json
import math
import io
import warnings
from http.server import HTTPServer, BaseHTTPRequestHandler
import numpy as np
import joblib
import pefile
import torch
import torch.nn as nn
import torch.nn.functional as F

warnings.filterwarnings('ignore')

# -------------------------------------------------------------
# 1. Load Model, Scaler & VAE Architecture
# -------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)

# Artifact paths
FEATURES_PATH = os.path.join(PROJECT_DIR, 'selected_features.json')
SCALER_PATH = os.path.join(PROJECT_DIR, 'scaler-V2.pkl')
RF_MODEL_PATH = os.path.join(PROJECT_DIR, 'malwareclassifier-V2-VAE.pkl')
VAE_MODEL_PATH = os.path.join(PROJECT_DIR, 'vae_model.pt')

with open(FEATURES_PATH, 'r') as f:
    IMPORTANT_FEATURES = json.load(f)

SCALER = joblib.load(SCALER_PATH)
RF_MODEL = joblib.load(RF_MODEL_PATH)

INPUT_DIM = len(IMPORTANT_FEATURES)
LATENT_DIM = 8

class VAE(nn.Module):
    def __init__(self, input_dim=INPUT_DIM, latent_dim=LATENT_DIM):
        super(VAE, self).__init__()
        self.enc1 = nn.Linear(input_dim, 32)
        self.enc2 = nn.Linear(32, 16)
        self.fc_mean = nn.Linear(16, latent_dim)
        self.fc_log_var = nn.Linear(16, latent_dim)
        self.dec1 = nn.Linear(latent_dim, 16)
        self.dec2 = nn.Linear(16, 32)
        self.dec_out = nn.Linear(32, input_dim)

    def encode(self, x):
        h = F.relu(self.enc1(x))
        h = F.relu(self.enc2(h))
        return self.fc_mean(h), self.fc_log_var(h)

    def decode(self, z):
        h = F.relu(self.dec1(z))
        h = F.relu(self.dec2(h))
        return self.dec_out(h)

    def forward(self, x):
        mean, log_var = self.encode(x)
        return mean, self.decode(mean)

VAE_MODEL = VAE(INPUT_DIM, LATENT_DIM)
VAE_MODEL.load_state_dict(torch.load(VAE_MODEL_PATH, map_location='cpu'))
VAE_MODEL.eval()
print(f"Loaded ML & DL artifacts successfully. Features: {len(IMPORTANT_FEATURES)}")

# -------------------------------------------------------------
# 2. PE Feature Extraction Function
# -------------------------------------------------------------
def extract_pe_features(byte_data):
    try:
        pe = pefile.PE(data=byte_data)
    except Exception as e:
        return None, None, f"Invalid PE File: Unable to parse Windows headers ({str(e)})"

    try:
        opt = getattr(pe, 'OPTIONAL_HEADER', None)
        file_hdr = getattr(pe, 'FILE_HEADER', None)

        export_dir = None
        if opt and hasattr(opt, 'DATA_DIRECTORY') and len(opt.DATA_DIRECTORY) > 0:
            export_dir = opt.DATA_DIRECTORY[0]

        import_dir = None
        if opt and hasattr(opt, 'DATA_DIRECTORY') and len(opt.DATA_DIRECTORY) > 1:
            import_dir = opt.DATA_DIRECTORY[1]

        entropies = [s.get_entropy() for s in pe.sections] if hasattr(pe, 'sections') else []
        chars = [s.Characteristics for s in pe.sections] if hasattr(pe, 'sections') else []
        virtual_sizes = [s.Misc_VirtualSize for s in pe.sections] if hasattr(pe, 'sections') else []

        raw_features = {
            'MajorLinkerVersion': getattr(opt, 'MajorLinkerVersion', 0) if opt else 0,
            'MinorOperatingSystemVersion': getattr(opt, 'MinorOperatingSystemVersion', 0) if opt else 0,
            'MajorSubsystemVersion': getattr(opt, 'MajorSubsystemVersion', 0) if opt else 0,
            'SizeOfStackReserve': getattr(opt, 'SizeOfStackReserve', 0) if opt else 0,
            'TimeDateStamp': getattr(file_hdr, 'TimeDateStamp', 0) if file_hdr else 0,
            'MajorOperatingSystemVersion': getattr(opt, 'MajorOperatingSystemVersion', 0) if opt else 0,
            'Characteristics': getattr(file_hdr, 'Characteristics', 0) if file_hdr else 0,
            'ImageBase': getattr(opt, 'ImageBase', 0) if opt else 0,
            'Subsystem': getattr(opt, 'Subsystem', 0) if opt else 0,
            'MinorImageVersion': getattr(opt, 'MinorImageVersion', 0) if opt else 0,
            'MinorSubsystemVersion': getattr(opt, 'MinorSubsystemVersion', 0) if opt else 0,
            'SizeOfInitializedData': getattr(opt, 'SizeOfInitializedData', 0) if opt else 0,
            'DllCharacteristics': getattr(opt, 'DllCharacteristics', 0) if opt else 0,
            'DirectoryEntryExport': 1 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0,
            'ImageDirectoryEntryExport': export_dir.Size if export_dir else 0,
            'CheckSum': getattr(opt, 'CheckSum', 0) if opt else 0,
            'DirectoryEntryImportSize': import_dir.Size if import_dir else 0,
            'SectionMaxChar': max(chars) if chars else 0,
            'MajorImageVersion': getattr(opt, 'MajorImageVersion', 0) if opt else 0,
            'AddressOfEntryPoint': getattr(opt, 'AddressOfEntryPoint', 0) if opt else 0,
            'SectionMinEntropy': float(min(entropies)) if entropies else 0.0,
            'SizeOfHeaders': getattr(opt, 'SizeOfHeaders', 0) if opt else 0,
            'SectionMinVirtualsize': min(virtual_sizes) if virtual_sizes else 0
        }

        metadata = {
            'sections_count': len(pe.sections) if hasattr(pe, 'sections') else 0,
            'machine': hex(getattr(file_hdr, 'Machine', 0)) if file_hdr else 'N/A',
            'subsystem_code': getattr(opt, 'Subsystem', 0) if opt else 0,
            'entry_point': hex(getattr(opt, 'AddressOfEntryPoint', 0)) if opt else '0x0',
            'image_base': hex(getattr(opt, 'ImageBase', 0)) if opt else '0x0',
            'has_imports': hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'),
            'has_exports': hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'),
            'timestamp': getattr(file_hdr, 'TimeDateStamp', 0) if file_hdr else 0,
            'sections': [
                {
                    'name': (s.Name.decode('utf-8', errors='ignore') if hasattr(s.Name, 'decode') else str(s.Name)).strip('\x00'),
                    'entropy': round(s.get_entropy(), 4),
                    'virtual_size': getattr(s, 'Misc_VirtualSize', getattr(s, 'VirtualSize', 0)),
                    'raw_size': getattr(s, 'SizeOfRawData', 0)
                } for s in pe.sections[:6]
            ] if hasattr(pe, 'sections') else []
        }

        return raw_features, metadata, None
    except Exception as e:
        return None, None, f"PE Analysis Error: {str(e)}"
    finally:
        try:
            pe.close()
        except Exception:
            pass

# -------------------------------------------------------------
# 3. HTTP Request Handler
# -------------------------------------------------------------
class MalwareDetectionHandler(BaseHTTPRequestHandler):

    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        # Serve index.html or static files
        if self.path == '/' or self.path == '/index.html':
            filepath = os.path.join(BASE_DIR, 'index.html')
            content_type = 'text/html; charset=utf-8'
        elif self.path.startswith('/static/'):
            filename = self.path[8:].split('?')[0]
            filepath = os.path.join(BASE_DIR, 'static', filename)
            if filename.endswith('.css'):
                content_type = 'text/css'
            elif filename.endswith('.js'):
                content_type = 'application/javascript'
            elif filename.endswith('.png'):
                content_type = 'image/png'
            elif filename.endswith('.svg'):
                content_type = 'image/svg+xml'
            else:
                content_type = 'application/octet-stream'
        elif self.path == '/api/health':
            self.send_response(200)
            self._send_cors_headers()
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'online', 'features': len(IMPORTANT_FEATURES)}).encode())
            return
        else:
            self.send_error(404, "File not found")
            return

        if os.path.exists(filepath):
            self.send_response(200)
            self._send_cors_headers()
            self.send_header('Content-Type', content_type)
            self.end_headers()
            with open(filepath, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File not found")

    def do_POST(self):
        if self.path == '/api/analyze':
            try:
                content_type = self.headers.get('Content-Type', '')
                if not content_type.startswith('multipart/form-data'):
                    self._json_response(400, {'error': 'Content-Type must be multipart/form-data'})
                    return

                # Read body
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)

                # Parse multipart
                fields = self._parse_multipart(body, content_type)
                if 'file' not in fields:
                    self._json_response(400, {'error': 'No file was provided in the upload request.'})
                    return

                filename = fields['file']['filename']
                file_bytes = fields['file']['data']

                # Strict validation of file extension
                ext = os.path.splitext(filename)[1].lower()
                if ext not in ['.exe', '.dll']:
                    self._json_response(400, {
                        'error': f"Invalid format '{ext}'. Only Windows executable (.exe) and dynamic-link library (.dll) files are accepted."
                    })
                    return

                # Extract PE features
                raw_feats, metadata, err = extract_pe_features(file_bytes)
                if err:
                    self._json_response(422, {'error': err, 'filename': filename})
                    return

                # Feature array aligned with IMPORTANT_FEATURES
                feat_values = [float(raw_feats[f]) for f in IMPORTANT_FEATURES]
                feature_vec = np.array([feat_values], dtype=np.float32)

                # Standard scale
                scaled_vec = SCALER.transform(feature_vec)

                # VAE forward pass for latent embedding & reconstruction error
                with torch.no_grad():
                    t_in = torch.tensor(scaled_vec, dtype=torch.float32)
                    latent_mean, recon = VAE_MODEL(t_in)
                    latent_np = latent_mean.numpy()
                    recon_np = recon.numpy()
                    reconstruction_error = float(np.mean(np.square(scaled_vec - recon_np)))

                # Combine scaled features + 8 VAE latent dimensions
                combined_features = np.hstack((scaled_vec, latent_np))

                # Random Forest Prediction
                pred_label = int(RF_MODEL.predict(combined_features)[0])
                pred_probs = RF_MODEL.predict_proba(combined_features)[0]

                prob_safe = float(pred_probs[0])
                prob_malware = float(pred_probs[1])

                # Anomaly classification status
                is_anomaly = reconstruction_error > 0.65

                # Top indicative features from the extracted sample
                key_indicators = [
                    {'name': 'MajorLinkerVersion', 'value': raw_feats['MajorLinkerVersion'], 'desc': 'Linker toolchain major version'},
                    {'name': 'TimeDateStamp', 'value': raw_feats['TimeDateStamp'], 'desc': 'POSIX compile timestamp'},
                    {'name': 'SizeOfStackReserve', 'value': f"{raw_feats['SizeOfStackReserve']:,} bytes", 'desc': 'Process stack memory footprint'},
                    {'name': 'ImageBase', 'value': hex(raw_feats['ImageBase']), 'desc': 'Preferred load address in RAM'},
                    {'name': 'MajorSubsystemVersion', 'value': raw_feats['MajorSubsystemVersion'], 'desc': 'Target subsystem version'},
                    {'name': 'SectionMinEntropy', 'value': round(raw_feats['SectionMinEntropy'], 3), 'desc': 'Minimum section code entropy'},
                    {'name': 'DirectoryEntryExport', 'value': 'Yes' if raw_feats['DirectoryEntryExport'] == 1 else 'No', 'desc': 'Exports directory presence'},
                    {'name': 'Characteristics', 'value': hex(raw_feats['Characteristics']), 'desc': 'Header file characteristics bitmask'}
                ]

                response_data = {
                    'filename': filename,
                    'file_size': len(file_bytes),
                    'file_type': 'Dynamic Link Library (.dll)' if ext == '.dll' else 'Windows Executable (.exe)',
                    'is_malware': bool(pred_label == 1),
                    'verdict': 'MALWARE' if pred_label == 1 else 'SAFE',
                    'confidence_malware': round(prob_malware * 100, 2),
                    'confidence_safe': round(prob_safe * 100, 2),
                    'vae': {
                        'reconstruction_error': round(reconstruction_error, 5),
                        'is_anomaly': is_anomaly,
                        'latent_vector': [round(float(x), 4) for x in latent_np[0].tolist()]
                    },
                    'metadata': metadata,
                    'key_features': key_indicators
                }

                self._json_response(200, response_data)

            except Exception as e:
                self._json_response(500, {'error': f"Internal analysis failure: {str(e)}"})
        else:
            self.send_error(404, "Endpoint not found")

    def _json_response(self, code, data):
        self.send_response(code)
        self._send_cors_headers()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _parse_multipart(self, body, content_type):
        boundary = content_type.split("boundary=")[1].encode()
        parts = body.split(b"--" + boundary)
        fields = {}

        for part in parts:
            if not part or part == b"--\r\n" or part == b"--":
                continue
            headers_part, _, file_data = part.partition(b"\r\n\r\n")
            if file_data.endswith(b"\r\n"):
                file_data = file_data[:-2]

            headers_str = headers_part.decode('utf-8', errors='ignore')
            if 'Content-Disposition' in headers_str:
                disposition = headers_str.split('Content-Disposition:')[1].split('\r\n')[0]
                field_name = None
                filename = None
                for param in disposition.split(';'):
                    param = param.strip()
                    if param.startswith('name='):
                        field_name = param.split('=')[1].strip('"\'')
                    elif param.startswith('filename='):
                        filename = param.split('=')[1].strip('"\'')

                if field_name == 'file' and filename:
                    fields['file'] = {
                        'filename': filename,
                        'data': file_data
                    }
        return fields

def run_server(port=8000):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, MalwareDetectionHandler)
    print(f"Malware Detector Web App running at http://localhost:{port}")
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
