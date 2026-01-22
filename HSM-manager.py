#!/usr/bin/env python3
"""
HSM Complete Manager - Unified Tool
Combines Key Generation, Import/Export, Key Block Analysis, and HSM Monitoring
"""

import socket
import os
import csv
import base64
import string
import json
from struct import *
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import webbrowser
import time
import io

class HSMManager:
    """Unified HSM Manager combining all operations"""
    
    def __init__(self, config_file='hsm_config.json'):
        self.VERSION = "2.1.0.0"
        
        # HSM Commands
        self.HSM_CMD_GENERATE = "A0"
        self.HSM_RESPONCE_GENERATE = "A1"
        self.HSM_CMD_IMPORT = "A6"
        self.HSM_RESPONCE_IMPORT = "A7"
        self.HSM_CMD_EXPORT = "A8"
        self.HSM_RESPONCE_EXPORT = "A9"
        self.HSM_CMD_LOADING = "J2"
        self.HSM_RESPONSE_LOADING = "J3"
        self.HSM_CMD_VOLUMES = "J4"
        self.HSM_RESPONSE_VOLUMES = "J5"
        self.MESSAGE_TRAILER = "TRLRD"
        
        # Load configuration from file
        self.load_config(config_file)
        
        # Data storage
        self.generate_keys = []
        self.import_jobs = []
        self.export_jobs = []
        
        # Options
        self.EXP_OPTIONS = ['S','N','E']
        self.KEY_STATUS_OPTIONS = ['L','T']
        
        # Key Block Parser Maps
        self.KEY_USAGE_MAP = {
            'B0': 'Base Derivation Key (BDK)',
            'B1': 'DUKPT Initial Key (IKEY)',
            'C0': 'Card Verification Key',
            'D0': 'Data Encryption Key (Generic)',
            'E0': 'EMV Master Key: Application Cryptogram (MKAC)',
            'E1': 'EMV Master Key: Secure Messaging Confidentiality (MKSMC)',
            'E2': 'EMV Master Key: Secure Messaging Integrity (MKSMI)',
            'E3': 'EMV Master Key: Data Authentication Code (MKDAC)',
            'E4': 'EMV Master Key: Dynamic Numbers (MKDN)',
            'E5': 'EMV Master Key: Card Personalisation',
            'E6': 'EMV Master Key: Other',
            'I0': 'Initialization Value',
            'K0': 'Key Encryption/Wrapping Key (Generic)',
            'K1': 'Key Block Protection Key',
            'M0': 'ISO 16609 MAC algorithm 1 (3-DES)',
            'M1': 'ISO 9797-1 MAC algorithm 1',
            'M2': 'ISO 9797-1 MAC algorithm 2',
            'M3': 'ISO 9797-1 MAC algorithm 3',
            'M5': 'ISO 9797-1:1999 MAC algorithm 5',
            'M6': 'ISO 9797-1:2011 MAC algorithm 5/CMAC',
            'M7': 'HMAC Key',
            'P0': 'PIN Encryption Key (Generic)',
            'V0': 'PIN Verification Key (Generic)',
            'V1': 'PIN Verification Key (IBM 3624)',
            'V2': 'PIN Verification Key (Visa PVV)',
            '11': 'ZKA Master Key (AES only)'
        }
        
        self.ALGORITHM_MAP = {
            'A': 'AES',
            'D': 'DES',
            'E': 'Elliptic Curve',
            'H': 'HMAC',
            'R': 'RSA',
            'S': 'DSA',
            'T': 'Triple DES (TDES)'
        }
        
        self.MODE_OF_USE_MAP = {
            'B': 'Both Encrypt and Decrypt',
            'C': 'MAC Calculate (Generate or Verify)',
            'D': 'Decrypt Only',
            'E': 'Encrypt Only',
            'G': 'MAC Generate Only',
            'N': 'No special restrictions',
            'S': 'Signature Generation Only',
            'T': 'Both Sign and Decrypt',
            'V': 'MAC Verify Only',
            'X': 'Key Derivation',
            'Y': 'Key used to create key variants'
        }
        
        self.EXPORTABILITY_MAP = {
            'E': 'Exportable in trusted Key Block only',
            'N': 'No export permitted',
            'S': 'Sensitive - export permitted if enabled'
        }
        
        self.VERSION_MAP = {
            'A': 'TR-31:2005 - Key Variant Binding Method (deprecated)',
            'B': 'TR-31:2010 - Key Derivation Binding Method',
            'C': 'TR-31:2010 - Key Variant Binding Method',
            'D': 'TR-31:2018 - AES Key Derivation Binding Method'
        }
    
    def load_config(self, config_file):
        """Load HSM configuration from JSON file"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.hsm_ip = config.get('hsm_ip')
                    self.hsm_port = config.get('hsm_port', 1500)
                    self.output_path = config.get('output_path', os.path.expanduser("~/hsm_output"))
                    self.debug_mode = config.get('debug_mode', False)
            else:
                raise FileNotFoundError(
                    f"Configuration file '{config_file}' not found.\n"
                    f"Please create it from hsm_config.example.json"
                )
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}")
        except Exception as e:
            raise Exception(f"Error loading configuration: {e}")
        
        # Validate required configuration
        if not self.hsm_ip:
            raise ValueError("hsm_ip must be configured in hsm_config.json")
    
    def find_hsm_hostname(self):
        if not self.hsm_ip:
            raise ValueError("HSM IP address must be configured")
        return self.hsm_ip
    
    def calc_head_lenght_hex(self, HEAD_VAL):
        SIZE = len(HEAD_VAL) + 2
        SIZE_HEX = format(SIZE, '02X')
        return SIZE_HEX
    
    def cmd_invoke(self, HOST_COMMAND):
        SIZE = pack('>h', len(HOST_COMMAND))
        MESSAGE = SIZE + HOST_COMMAND.encode()
        BUFFER_SIZE = 8192  # Increased for monitoring commands
        
        HOST = self.find_hsm_hostname()
        
        if self.debug_mode:
            print(f"DEBUG: Connecting to HSM: {HOST}:{self.hsm_port}")
            print(f"DEBUG: Command (HEX): {bytes.hex(MESSAGE)}")
        
        CONNECTION = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CONNECTION.connect((HOST, self.hsm_port))
        CONNECTION.send(MESSAGE)
        DATA = CONNECTION.recv(BUFFER_SIZE)
        CONNECTION.close()
        
        if self.debug_mode:
            print(f"DEBUG: Response (HEX): {bytes.hex(DATA)}")
        
        return DATA
    
    # ==================== CSV IMPORT/EXPORT ====================
    
    def import_csv_generate(self, csv_content):
        """Import CSV for key generation"""
        try:
            csv_reader = csv.DictReader(io.StringIO(csv_content), delimiter=';')
            imported_keys = []
            
            for row_num, row in enumerate(csv_reader, start=1):
                row = {k.strip(): v.strip() if v else '' for k, v in row.items()}
                
                if not row.get('cb_description') or not row.get('key_scheme'):
                    raise ValueError(f"Row {row_num}: Missing required fields")
                
                key_data = {
                    'cb_description': row.get('cb_description', ''),
                    'key_scheme': row.get('key_scheme', ''),
                    'lmk_identifier': row.get('lmk_identifier', ''),
                    'key_usage': row.get('key_usage', ''),
                    'algorithm': row.get('algorithm', ''),
                    'mode_of_use': row.get('mode_of_use', ''),
                    'key_version_number': row.get('key_version_number', ''),
                    'exportability': row.get('exportability', 'S'),
                    'kb_opt_date': row.get('kb_opt_date') or datetime.now().strftime('%Y%m%d'),
                    'kb_opt_text': row.get('kb_opt_text', ''),
                    'kb_opt_idx': row.get('kb_opt_idx', ''),
                    'kb_opt_shared': row.get('kb_opt_shared', 'N'),
                    'kb_opt_status': row.get('kb_opt_status', 'L')
                }
                
                imported_keys.append(key_data)
            
            return {'success': True, 'keys': imported_keys, 'count': len(imported_keys)}
        except Exception as e:
            return {'success': False, 'error': str(e), 'count': 0}
    
    def export_template_generate_csv(self):
        """Generate CSV template for key generation"""
        template_data = [{
            'cb_description': 'Example Key 1',
            'key_scheme': 'S',
            'lmk_identifier': '001',
            'key_usage': 'C0',
            'algorithm': 'A',
            'mode_of_use': 'E',
            'key_version_number': '01',
            'exportability': 'S',
            'kb_opt_date': datetime.now().strftime('%Y%m%d'),
            'kb_opt_text': 'Example description',
            'kb_opt_idx': '001',
            'kb_opt_shared': 'N',
            'kb_opt_status': 'L'
        }]
        
        output = io.StringIO()
        field_names = ['cb_description', 'key_scheme', 'lmk_identifier', 'key_usage', 
                      'algorithm', 'mode_of_use', 'key_version_number', 'exportability',
                      'kb_opt_date', 'kb_opt_text', 'kb_opt_idx', 'kb_opt_shared', 'kb_opt_status']
        writer = csv.DictWriter(output, fieldnames=field_names, delimiter=';')
        writer.writeheader()
        writer.writerows(template_data)
        return output.getvalue()
    
    def import_csv_for_import(self, csv_content):
        """Import CSV for import jobs"""
        try:
            csv_reader = csv.DictReader(io.StringIO(csv_content), delimiter=';')
            imported_jobs = []
            
            for row_num, row in enumerate(csv_reader, start=1):
                row = {k.strip(): v.strip() if v else '' for k, v in row.items()}
                
                if not row.get('zmk_key') or not row.get('working_key'):
                    raise ValueError(f"Row {row_num}: Missing required fields")
                
                job_data = {
                    'cb_description': row.get('cb_description', ''),
                    'zmk_key': row.get('zmk_key', ''),
                    'working_key': row.get('working_key', ''),
                    'key_scheme': row.get('key_scheme', 'S'),
                    'lmk_identifier': row.get('lmk_identifier', '00'),
                    'key_usage': row.get('key_usage', '')
                }
                
                imported_jobs.append(job_data)
            
            return {'success': True, 'jobs': imported_jobs, 'count': len(imported_jobs)}
        except Exception as e:
            return {'success': False, 'error': str(e), 'count': 0}
    
    def export_template_import_csv(self):
        """Generate CSV template for import operations"""
        template_data = [{
            'cb_description': 'Example Import',
            'zmk_key': 'S00096...',
            'working_key': 'S00120...',
            'key_scheme': 'S',
            'lmk_identifier': '00',
            'key_usage': 'P0'
        }]
        
        output = io.StringIO()
        field_names = ['cb_description', 'zmk_key', 'working_key', 'key_scheme', 
                      'lmk_identifier', 'key_usage']
        writer = csv.DictWriter(output, fieldnames=field_names, delimiter=';')
        writer.writeheader()
        writer.writerows(template_data)
        return output.getvalue()
    
    def import_csv_for_export(self, csv_content):
        """Import CSV for export jobs"""
        try:
            csv_reader = csv.DictReader(io.StringIO(csv_content), delimiter=';')
            imported_jobs = []
            
            for row_num, row in enumerate(csv_reader, start=1):
                row = {k.strip(): v.strip() if v else '' for k, v in row.items()}
                
                key_under_lmk = row.get('key_under_lmk') or row.get('working_key')
                
                if not row.get('zmk_key') or not key_under_lmk:
                    raise ValueError(f"Row {row_num}: Missing required fields")
                
                job_data = {
                    'cb_description': row.get('cb_description', ''),
                    'key_under_lmk': key_under_lmk,
                    'zmk_key': row.get('zmk_key', ''),
                    'key_scheme': row.get('key_scheme', 'S'),
                    'lmk_identifier': row.get('lmk_identifier', '00'),
                    'exportability': row.get('exportability', 'S'),
                    'key_ver_id': row.get('key_ver_id', '')
                }
                
                imported_jobs.append(job_data)
            
            return {'success': True, 'jobs': imported_jobs, 'count': len(imported_jobs)}
        except Exception as e:
            return {'success': False, 'error': str(e), 'count': 0}
    
    def export_template_export_csv(self):
        """Generate CSV template for export operations"""
        template_data = [{
            'cb_description': 'Example Export',
            'key_under_lmk': 'S00096...',
            'zmk_key': 'S00120...',
            'key_scheme': 'S',
            'lmk_identifier': '00',
            'exportability': 'S',
            'key_ver_id': 'C'
        }]
        
        output = io.StringIO()
        field_names = ['cb_description', 'key_under_lmk', 'zmk_key', 'key_scheme',
                      'lmk_identifier', 'exportability', 'key_ver_id']
        writer = csv.DictWriter(output, fieldnames=field_names, delimiter=';')
        writer.writeheader()
        writer.writerows(template_data)
        return output.getvalue()
    
    # ==================== KEY GENERATION (A0) ====================
    
    def process_generate_key(self, key_data):
        """Generate a key using A0 command"""
        kb_key_text = ""
        if key_data.get('kb_opt_text'):
            kb_key_text = "[" + key_data['kb_opt_text'].replace(" ","_")
        if key_data.get('kb_opt_idx'):
            kb_key_text = kb_key_text + "_idx" + key_data['kb_opt_idx']
        if key_data.get('kb_opt_shared') == 'Y':
            kb_key_text = kb_key_text + "_(Shared_Auth_CCMS)"
        if kb_key_text:
            kb_key_text = kb_key_text + "]"

        lenght_kb_opt_date = self.calc_head_lenght_hex('03' + key_data['kb_opt_date'])
        lenght_kb_key_text = self.calc_head_lenght_hex('05' + kb_key_text)
        lenght_kb_opt_status = self.calc_head_lenght_hex('01' + key_data['kb_opt_status'])

        lmk_identifier = key_data['lmk_identifier']
        if lmk_identifier and len(lmk_identifier) == 1:
            lmk_identifier = '00' + lmk_identifier

        key_version_number = key_data['key_version_number']
        if key_version_number and len(key_version_number) == 1:
            key_version_number = '00' + key_version_number

        HOST_COMMAND = ('HEAD' + self.HSM_CMD_GENERATE + '0' + 'FFF' + key_data['key_scheme'] + '%' + 
                       lmk_identifier + '#' + key_data['key_usage'] + key_data['algorithm'] + 
                       key_data['mode_of_use'] + key_version_number + key_data['exportability'] + '03' + '03' + 
                       lenght_kb_opt_date + key_data['kb_opt_date'] + '00' + lenght_kb_opt_status + 
                       key_data['kb_opt_status'] + '05' + lenght_kb_key_text + kb_key_text + '\x19' + self.MESSAGE_TRAILER)

        hsm_output = self.cmd_invoke(HOST_COMMAND)

        IDX_ret_code = hsm_output.find(self.HSM_RESPONCE_GENERATE.encode())
        RET_CODE = hsm_output[IDX_ret_code+2:IDX_ret_code+4]
        IDX_DELIMITER_CHAR = hsm_output.find(self.MESSAGE_TRAILER.encode())
        KB_KEY = hsm_output[IDX_ret_code+4:IDX_DELIMITER_CHAR-7]
        KB_KCV = hsm_output[IDX_DELIMITER_CHAR-7:IDX_DELIMITER_CHAR-1]

        if RET_CODE.decode("utf-8") != "00":
            raise Exception(f"HSM returned error code: {RET_CODE.decode('utf-8')}")

        return {
            "kcv": KB_KCV.decode("utf-8"),
            "kb_value": KB_KEY.decode("utf-8"),
            "status": "success"
        }
    
    def process_all_generate_keys(self):
        """Process all key generation jobs"""
        results = []
        now = datetime.now()
        datetime_str = now.strftime("%Y%m%d-%H%M%S")
        output_dir = os.path.join(self.output_path, f"LOG_generate_keys_{datetime_str}")
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"generate_keys_{datetime_str}_OUTPUT.csv")
            new_rows = []
            
            for i, key_data in enumerate(self.generate_keys):
                try:
                    result = self.process_generate_key(key_data.copy())
                    key_data.update(result)
                    new_rows.append(key_data)
                    
                    results.append({
                        'status': 'success',
                        'key': key_data['cb_description'],
                        'kcv': result['kcv'],
                        'message': 'Generated successfully'
                    })
                except Exception as e:
                    results.append({
                        'status': 'error',
                        'key': key_data['cb_description'],
                        'kcv': '',
                        'message': str(e)
                    })
            
            if new_rows:
                field_names = list(new_rows[0].keys())
                with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=field_names, delimiter=';')
                    writer.writeheader()
                    writer.writerows(new_rows)
                
                results.append({
                    'status': 'info',
                    'key': 'Output',
                    'kcv': '',
                    'message': f"Results saved to: {output_file}"
                })
        
        except Exception as e:
            results.append({
                'status': 'error',
                'key': 'System',
                'kcv': '',
                'message': str(e)
            })
        
        return results
    
    # ==================== KEY IMPORT (A6) ====================
    
    def process_import_key(self, job_data):
        """Import a key using A6 command"""
        key_type = 'FFF'
        zmk = job_data['zmk_key']
        key_under_zmk = job_data['working_key']
        key_scheme_lmk = job_data.get('key_scheme', 'S')
        
        HOST_COMMAND = f"HEAD{self.HSM_CMD_IMPORT}{key_type}{zmk}{key_under_zmk}{key_scheme_lmk}"
        
        if job_data.get('lmk_identifier'):
            HOST_COMMAND += f"%{job_data['lmk_identifier']}"
        
        HOST_COMMAND += '\x19' + self.MESSAGE_TRAILER
        
        hsm_output = self.cmd_invoke(HOST_COMMAND)
        
        IDX_ret_code = hsm_output.find(self.HSM_RESPONCE_IMPORT.encode())
        RET_CODE = hsm_output[IDX_ret_code+2:IDX_ret_code+4]
        
        if RET_CODE.decode("utf-8") != "00":
            raise Exception(f"HSM returned error code: {RET_CODE.decode('utf-8')}")
        
        IDX_DELIMITER = hsm_output.find(self.MESSAGE_TRAILER.encode())
        KEY_UNDER_LMK = hsm_output[IDX_ret_code+4:IDX_DELIMITER-7]
        KCV = hsm_output[IDX_DELIMITER-7:IDX_DELIMITER-1]
        
        return {
            'key_under_lmk': KEY_UNDER_LMK.decode("utf-8"),
            'kcv': KCV.decode("utf-8"),
            'status': 'success'
        }
    
    def process_all_imports(self):
        """Process all import jobs"""
        results = []
        now = datetime.now()
        datetime_str = now.strftime("%Y%m%d-%H%M%S")
        output_dir = os.path.join(self.output_path, f"LOG_import_keys_{datetime_str}")
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"import_keys_{datetime_str}_OUTPUT.csv")
            new_rows = []
            
            for job in self.import_jobs:
                try:
                    result = self.process_import_key(job.copy())
                    job.update(result)
                    new_rows.append(job)
                    
                    results.append({
                        'status': 'success',
                        'job': job['cb_description'],
                        'kcv': result['kcv'],
                        'message': 'Imported successfully'
                    })
                except Exception as e:
                    results.append({
                        'status': 'error',
                        'job': job['cb_description'],
                        'kcv': '',
                        'message': str(e)
                    })
            
            if new_rows:
                field_names = list(new_rows[0].keys())
                with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=field_names, delimiter=';')
                    writer.writeheader()
                    writer.writerows(new_rows)
                
                results.append({
                    'status': 'info',
                    'job': 'Output',
                    'kcv': '',
                    'message': f"Results saved to: {output_file}"
                })
        
        except Exception as e:
            results.append({
                'status': 'error',
                'job': 'System',
                'kcv': '',
                'message': str(e)
            })
        
        return results
    
    # ==================== KEY EXPORT (A8) ====================
    
    def process_export_key(self, job_data):
        """Export a key using A8 command"""
        key_type = 'FFF'
        zmk = job_data['zmk_key']
        key_under_lmk = job_data['key_under_lmk']
        key_scheme_zmk = job_data.get('key_scheme', 'S')
        
        HOST_COMMAND = f"HEAD{self.HSM_CMD_EXPORT}{key_type}{zmk}{key_under_lmk}{key_scheme_zmk}"
        
        if job_data.get('lmk_identifier'):
            HOST_COMMAND += f"%{job_data['lmk_identifier']}"
        
        if key_scheme_zmk == 'S' and job_data.get('exportability'):
            HOST_COMMAND += f"&{job_data['exportability']}"
        elif key_scheme_zmk not in ['X', 'Z', 'Y']:
            if job_data.get('exportability'):
                HOST_COMMAND += f"&{job_data['exportability']}"
            if job_data.get('key_ver_id'):
                HOST_COMMAND += f"!{job_data['key_ver_id']}"
        
        HOST_COMMAND += '\x19' + self.MESSAGE_TRAILER
        
        hsm_output = self.cmd_invoke(HOST_COMMAND)
        
        IDX_ret_code = hsm_output.find(self.HSM_RESPONCE_EXPORT.encode())
        RET_CODE = hsm_output[IDX_ret_code+2:IDX_ret_code+4]
        
        if RET_CODE.decode("utf-8") != "00":
            raise Exception(f"HSM returned error code: {RET_CODE.decode('utf-8')}")
        
        IDX_DELIMITER = hsm_output.find(self.MESSAGE_TRAILER.encode())
        KEY_UNDER_ZMK = hsm_output[IDX_ret_code+4:IDX_DELIMITER-7]
        KCV = hsm_output[IDX_DELIMITER-7:IDX_DELIMITER-1]
        
        return {
            'key_under_zmk': KEY_UNDER_ZMK.decode("utf-8"),
            'kcv': KCV.decode("utf-8"),
            'status': 'success'
        }
    
    def process_all_exports(self):
        """Process all export jobs"""
        results = []
        now = datetime.now()
        datetime_str = now.strftime("%Y%m%d-%H%M%S")
        output_dir = os.path.join(self.output_path, f"LOG_export_keys_{datetime_str}")
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"export_keys_{datetime_str}_OUTPUT.csv")
            new_rows = []
            
            for job in self.export_jobs:
                try:
                    result = self.process_export_key(job.copy())
                    job.update(result)
                    new_rows.append(job)
                    
                    results.append({
                        'status': 'success',
                        'job': job['cb_description'],
                        'kcv': result['kcv'],
                        'message': 'Exported successfully'
                    })
                except Exception as e:
                    results.append({
                        'status': 'error',
                        'job': job['cb_description'],
                        'kcv': '',
                        'message': str(e)
                    })
            
            if new_rows:
                field_names = list(new_rows[0].keys())
                with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=field_names, delimiter=';')
                    writer.writeheader()
                    writer.writerows(new_rows)
                
                results.append({
                    'status': 'info',
                    'job': 'Output',
                    'kcv': '',
                    'message': f"Results saved to: {output_file}"
                })
        
        except Exception as e:
            results.append({
                'status': 'error',
                'job': 'System',
                'kcv': '',
                'message': str(e)
            })
        
        return results
    
    # ==================== KEY BLOCK DECODER ====================
    
    def parse_key_block(self, key_block_input):
        """Parse and analyze a key block"""
        key_block = key_block_input.strip()
        
        result = {
            'scheme_tag': None,
            'is_thales': False,
            'header': {},
            'optional_blocks': [],
            'encrypted_key_data': '',
            'authenticator': '',
            'analysis': []
        }
        
        # Check scheme tag
        if key_block[0] in ['R', 'V', 'S']:
            result['scheme_tag'] = key_block[0]
            result['is_thales'] = (key_block[0] == 'S')
            key_block = key_block[1:]
            
            scheme_names = {
                'R': 'X9.143/TR-31 Key Block',
                'V': 'VeriFone/GISKE Key Block',
                'S': 'Thales Key Block'
            }
            result['analysis'].append(f"Scheme Tag: {result['scheme_tag']} ({scheme_names[result['scheme_tag']]})")
        
        if len(key_block) < 16:
            raise ValueError("Key block too short (minimum 16 characters for header)")
        
        # Parse header
        header = key_block[:16]
        result['header'] = {
            'version_id': header[0],
            'key_block_length': header[1:5],
            'key_usage': header[5:7],
            'algorithm': header[7],
            'mode_of_use': header[8],
            'key_version': header[9:11],
            'exportability': header[11],
            'num_optional_blocks': int(header[12:14]),
            'reserved': header[14:16]
        }
        
        h = result['header']
        result['analysis'].append(f"Version: {h['version_id']} - {self.VERSION_MAP.get(h['version_id'], 'Unknown')}")
        result['analysis'].append(f"Length: {h['key_block_length']} bytes")
        result['analysis'].append(f"Key Usage: {h['key_usage']} - {self.KEY_USAGE_MAP.get(h['key_usage'], 'Unknown')}")
        result['analysis'].append(f"Algorithm: {h['algorithm']} - {self.ALGORITHM_MAP.get(h['algorithm'], 'Unknown')}")
        result['analysis'].append(f"Mode:{h['mode_of_use']} - {self.MODE_OF_USE_MAP.get(h['mode_of_use'], 'Unknown')}")
        result['analysis'].append(f"Exportability: {h['exportability']} - {self.EXPORTABILITY_MAP.get(h['exportability'], 'Unknown')}")
        
        # Parse optional blocks
        auth_length = 16 if h['version_id'] == 'D' else 8
        pos = 16
        
        for i in range(h['num_optional_blocks']):
            if pos + 4 > len(key_block):
                break
            
            block_id = key_block[pos:pos+2]
            block_length_str = key_block[pos+2:pos+4]
            
            if block_length_str == '00':
                num_length_bytes = int(key_block[pos+4:pos+6], 16)
                actual_length = int(key_block[pos+6:pos+6+num_length_bytes*2], 16)
                block_data = key_block[pos+6+num_length_bytes*2:pos+actual_length]
                pos += actual_length
            else:
                actual_length = int(block_length_str, 16)
                block_data = key_block[pos+4:pos+actual_length]
                pos += actual_length
            
            result['optional_blocks'].append({
                'id': block_id,
                'length': actual_length,
                'data': block_data
            })
        
        # Extract encrypted key data and authenticator
        remaining_data = key_block[pos:]
        result['encrypted_key_data'] = remaining_data[:-auth_length] if len(remaining_data) > auth_length else ''
        result['authenticator'] = remaining_data[-auth_length:] if len(remaining_data) >= auth_length else ''
        
        return result
    
    # ==================== HSM MONITORING (J2 & J4) ====================
    
    def get_hsm_loading(self):
        """Get HSM loading information using J2 command"""
        HOST_COMMAND = 'HEAD' + self.HSM_CMD_LOADING + '\x19' + self.MESSAGE_TRAILER
        
        hsm_output = self.cmd_invoke(HOST_COMMAND)
        
        IDX_ret_code = hsm_output.find(self.HSM_RESPONSE_LOADING.encode())
        if IDX_ret_code == -1:
            raise Exception("Invalid response from HSM")
        
        RET_CODE = hsm_output[IDX_ret_code+2:IDX_ret_code+4]
        
        if RET_CODE.decode("utf-8") != "00":
            raise Exception(f"HSM returned error code: {RET_CODE.decode('utf-8')}")
        
        IDX_DELIMITER = hsm_output.find(self.MESSAGE_TRAILER.encode())
        response_data = hsm_output[IDX_ret_code+4:IDX_DELIMITER].decode("utf-8")
        
        # Parse response
        serial_number = response_data[0:12]
        start_date = response_data[12:18]
        start_time = response_data[18:24]
        end_date = response_data[24:30]
        end_time = response_data[30:36]
        current_date = response_data[36:42]
        current_time = response_data[42:48]
        seconds = int(response_data[48:58])
        
        # Parse loading ranges - formato: START(3)END(3)PERIODS(10) ripetuto
        ranges_data = response_data[58:]
        loading_ranges = []
        
        if self.debug_mode:
            print(f"DEBUG J2: ranges_data = '{ranges_data}'")
            print(f"DEBUG J2: ranges_data length = {len(ranges_data)}")
        
        # Each range is 16 characters: START(3) + END(3) + PERIODS(10)
        # Plus semicolon separator
        pos = 0
        while pos < len(ranges_data):
            # Skip semicolons
            if ranges_data[pos:pos+1] == ';':
                pos += 1
                continue
                
            # Need at least 16 characters for a complete range
            if pos + 16 > len(ranges_data):
                break
                
            try:
                start_str = ranges_data[pos:pos+3]
                end_str = ranges_data[pos+3:pos+6]
                periods_str = ranges_data[pos+6:pos+16]
                
                start_pct = int(start_str)
                end_pct = int(end_str)
                time_periods = int(periods_str)
                
                if self.debug_mode:
                    print(f"DEBUG J2: Parsed range: {start_pct}-{end_pct}% = {time_periods} periods")
                
                loading_ranges.append({
                    'start_percentage': start_pct,
                    'end_percentage': end_pct,
                    'time_periods': time_periods
                })
                
                # Move to next range (16 chars + possible semicolon)
                pos += 16
                if pos < len(ranges_data) and ranges_data[pos:pos+1] == ';':
                    pos += 1
                    
            except (ValueError, IndexError) as e:
                if self.debug_mode:
                    print(f"DEBUG J2: Error parsing at position {pos}: {e}")
                    print(f"DEBUG J2: Remaining data: '{ranges_data[pos:]}'")
                break
        
        return {
            'serial_number': serial_number,
            'start_date': start_date,
            'start_time': start_time,
            'end_date': end_date,
            'end_time': end_time,
            'current_date': current_date,
            'current_time': current_time,
            'seconds': seconds,
            'loading_ranges': loading_ranges,
            'is_active': (current_date == end_date and current_time == end_time)
        }
    
    def get_command_volumes(self):
        """Get host command volumes using J4 command"""
        HOST_COMMAND = 'HEAD' + self.HSM_CMD_VOLUMES + '\x19' + self.MESSAGE_TRAILER
        
        hsm_output = self.cmd_invoke(HOST_COMMAND)
        
        IDX_ret_code = hsm_output.find(self.HSM_RESPONSE_VOLUMES.encode())
        if IDX_ret_code == -1:
            raise Exception("Invalid response from HSM")
        
        RET_CODE = hsm_output[IDX_ret_code+2:IDX_ret_code+4]
        
        if RET_CODE.decode("utf-8") != "00":
            raise Exception(f"HSM returned error code: {RET_CODE.decode('utf-8')}")
        
        IDX_DELIMITER = hsm_output.find(self.MESSAGE_TRAILER.encode())
        response_data = hsm_output[IDX_ret_code+4:IDX_DELIMITER].decode("utf-8")
        
        # Parse response
        serial_number = response_data[0:12]
        start_date = response_data[12:18]
        start_time = response_data[18:24]
        end_date = response_data[24:30]
        end_time = response_data[30:36]
        current_date = response_data[36:42]
        current_time = response_data[42:48]
        seconds = int(response_data[48:58])
        
        # Parse command volumes
        commands_data = response_data[58:]
        command_volumes = []
        
        pos = 0
        while pos + 14 <= len(commands_data):
            # Verifica che ci siano almeno 14 caratteri rimanenti
            if pos + 14 > len(commands_data):
                break
            
            cmd_code = commands_data[pos:pos+2]
            transactions_str = commands_data[pos+2:pos+14]
            
            #Verifica che i dati siano validi

            if not cmd_code or not transactions_str:
                break
            
            try:
                transactions = int(transactions_str)
                command_volumes.append({
                'command_code': cmd_code,
                'transactions': transactions
                 })
                pos += 14
            except ValueError:
                break
        
        # Sort by transaction count descending
        command_volumes.sort(key=lambda x: x['transactions'], reverse=True)
        
        return {
            'serial_number': serial_number,
            'start_date': start_date,
            'start_time': start_time,
            'end_date': end_date,
            'end_time': end_time,
            'current_date': current_date,
            'current_time': current_time,
            'seconds': int(seconds),
            'command_volumes': command_volumes,
            'is_active': (current_date == end_date and current_time == end_time)
        }


# Global instance
hsm_manager = HSMManager()


class UnifiedRequestHandler(BaseHTTPRequestHandler):
    """Unified HTTP request handler for all HSM operations"""
    
    def do_GET(self):
        if self.path == '/':
            self.serve_html()
        elif self.path == '/api/generate_keys':
            self.serve_generate_keys()
        elif self.path == '/api/import_jobs':
            self.serve_import_jobs()
        elif self.path == '/api/export_jobs':
            self.serve_export_jobs()
        elif self.path == '/api/config':
            self.get_config()
        elif self.path == '/api/template/generate':
            self.download_template_generate()
        elif self.path == '/api/template/import':
            self.download_template_import()
        elif self.path == '/api/template/export':
            self.download_template_export()
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/api/add_generate_key':
            self.add_generate_key()
        elif self.path == '/api/process_generate':
            self.process_generate()
        elif self.path == '/api/clear_generate':
            self.clear_generate()
        elif self.path == '/api/import_csv_generate':
            self.import_csv_generate()
        elif self.path == '/api/add_import_job':
            self.add_import_job()
        elif self.path == '/api/process_imports':
            self.process_imports()
        elif self.path == '/api/clear_imports':
            self.clear_imports()
        elif self.path == '/api/import_csv_import':
            self.import_csv_import()
        elif self.path == '/api/add_export_job':
            self.add_export_job()
        elif self.path == '/api/process_exports':
            self.process_exports()
        elif self.path == '/api/clear_exports':
            self.clear_exports()
        elif self.path == '/api/import_csv_export':
            self.import_csv_export()
        elif self.path == '/api/parse_keyblock':
            self.parse_keyblock()
        elif self.path == '/api/set_config':
            self.set_config()
        elif self.path == '/api/get_hsm_loading':
            self.get_hsm_loading()
        elif self.path == '/api/get_command_volumes':
            self.get_command_volumes()
        else:
            self.send_error(404)
    
    def do_DELETE(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode())
        index = data.get('index')
        
        if self.path == '/api/generate_keys':
            if index is not None and 0 <= index < len(hsm_manager.generate_keys):
                hsm_manager.generate_keys.pop(index)
                response = {'success': True}
            else:
                response = {'success': False}
        elif self.path == '/api/import_jobs':
            if index is not None and 0 <= index < len(hsm_manager.import_jobs):
                hsm_manager.import_jobs.pop(index)
                response = {'success': True}
            else:
                response = {'success': False}
        elif self.path == '/api/export_jobs':
            if index is not None and 0 <= index < len(hsm_manager.export_jobs):
                hsm_manager.export_jobs.pop(index)
                response = {'success': True}
            else:
                response = {'success': False}
        else:
            response = {'success': False}
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def serve_html(self):
        html_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HSM Complete Manager</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .header .version { font-size: 0.9em; opacity: 0.9; }
        .tabs { display: flex; background: #f8f9fa; border-bottom: 3px solid #667eea; flex-wrap: wrap; }
        .tab { flex: 1; min-width: 150px; padding: 20px; text-align: center; cursor: pointer; font-weight: bold; font-size: 1.1em; transition: all 0.3s; background: #f8f9fa; color: #333; border-right: 1px solid #ddd; }
        .tab:last-child { border-right: none; }
        .tab:hover { background: #e9ecef; }
        .tab.active { background: white; color: #667eea; border-bottom: 3px solid #667eea; margin-bottom: -3px; }
        .tab-content { display: none; padding: 30px; }
        .tab-content.active { display: block; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .form-section { background: #f8f9fa; padding: 25px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #667eea; }
        .section-title { color: #667eea; font-size: 1.3em; font-weight: bold; margin-bottom: 20px; display: flex; align-items: center; }
        .section-title::before { content: '▸'; margin-right: 10px; }
        .form-group { margin-bottom: 15px; display: grid; grid-template-columns: 200px 1fr; align-items: center; gap: 15px; }
        .form-group label { font-weight: 600; color: #495057; }
        .form-group input, .form-group select, .form-group textarea { padding: 10px; border: 2px solid #dee2e6; border-radius: 5px; font-size: 1em; transition: border-color 0.3s; }
        .form-group input:focus, .form-group select:focus, .form-group textarea:focus { outline: none; border-color: #667eea; }
        .btn { padding: 12px 25px; margin: 5px; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; font-size: 1em; transition: all 0.3s; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 12px rgba(0,0,0,0.15); }
        .btn-primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .btn-success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); color: white; }
        .btn-danger { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); color: white; }
        .btn-secondary { background: linear-gradient(135deg, #757f9a 0%, #d7dde8 100%); color: #333; }
        .btn-info { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; }
        .button-group { text-align: center; margin: 25px 0; }
        .table-container { overflow-x: auto; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .data-table { width: 100%; border-collapse: collapse; }
        .data-table th { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; text-align: left; font-weight: 600; }
        .data-table td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        .data-table tr:hover { background: #f8f9fa; }
        .data-table tr:last-child td { border-bottom: none; }
        .log-box { width: 100%; height: 250px; border: 2px solid #dee2e6; padding: 15px; font-family: 'Courier New', monospace; font-size: 0.9em; overflow-y: scroll; background: #f8f9fa; border-radius: 8px; }
        .log-box::-webkit-scrollbar { width: 8px; }
        .log-box::-webkit-scrollbar-track { background: #f1f1f1; }
        .log-box::-webkit-scrollbar-thumb { background: #667eea; border-radius: 4px; }
        .status-success { color: #28a745; font-weight: bold; }
        .status-error { color: #dc3545; font-weight: bold; }
        .status-info { color: #17a2b8; font-weight: bold; }
        .decoder-output { background: #2d3748; color: #48bb78; padding: 20px; border-radius: 10px; font-family: 'Courier New', monospace; white-space: pre-wrap; max-height: 500px; overflow-y: auto; }
        .decoder-input { width: 100%; min-height: 100px; font-family: 'Courier New', monospace; }
        .count-badge { background: #667eea; color: white; padding: 5px 12px; border-radius: 20px; font-size: 0.9em; margin-left: 10px; }
        .chart-container { background: white; padding: 20px; border-radius: 10px; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .chart-wrapper { position: relative; height: 400px; }
        .monitor-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .info-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .info-card .label { font-size: 0.9em; opacity: 0.9; margin-bottom: 5px; }
        .info-card .value { font-size: 1.5em; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 HSM Complete Manager</h1>
            <div class="version">Version 2.1 - Complete HSM Management & Monitoring</div>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('generate')">🔑 Generate Keys (A0)</div>
            <div class="tab" onclick="switchTab('import')">📥 Import Keys (A6)</div>
            <div class="tab" onclick="switchTab('export')">📤 Export Keys (A8)</div>
            <div class="tab" onclick="switchTab('decoder')">🔍 Key Block Decoder</div>
            <div class="tab" onclick="switchTab('monitoring')">📊 HSM Monitoring</div>
            <div class="tab" onclick="switchTab('config')">⚙️ Configuration</div>
        </div>
        
        <!-- GENERATE TAB -->
        <div id="generateTab" class="tab-content active">
            <!-- CSV Import Section -->
            <div class="form-section" style="background: linear-gradient(135deg, #e8f5e8 0%, #d4edda 100%); border-left: 5px solid #27ae60; margin-bottom: 25px;">
                <div class="section-title" style="color: #27ae60;">📄 CSV Bulk Import - Generate Keys</div>
                <div style="display: grid; gap: 15px;">
                    <div>
                        <label style="display: block; margin-bottom: 8px; font-weight: 600;">Select CSV File:</label>
                        <input type="file" id="csvGenerateFile" accept=".csv" style="width: 100%; padding: 10px; border: 2px solid #27ae60; border-radius: 5px; background: white;" />
                    </div>
                    <div style="display: flex; gap: 10px; justify-content: center;">
                        <button class="btn btn-info" onclick="importCSVGenerate()">📥 Import CSV</button>
                        <button class="btn btn-secondary" onclick="downloadTemplateGenerate()">📋 Download Template</button>
                    </div>
                    <div style="font-size: 0.9em; color: #555; text-align: center;">
                        💡 Use the template to bulk-add multiple key generation jobs
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Add Single Key Generation Job</div>
                <div class="form-group">
                    <label>Description*:</label>
                    <input type="text" id="gen_description" required>
                </div>
                <div class="form-group">
                    <label>Key Scheme*:</label>
                    <select id="gen_key_scheme">
                        <option value="">-- Select --</option>
                        <option value="S">S - Thales Key Block</option>
                        <option value="R">R - TR-31</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>LMK Identifier:</label>
                    <input type="text" id="gen_lmk_id" placeholder="e.g., 00">
                </div>
                <div class="form-group">
                    <label>Key Usage:</label>
                    <input type="text" id="gen_key_usage" placeholder="e.g., C0, P0">
                </div>
                <div class="form-group">
                    <label>Algorithm:</label>
                    <select id="gen_algorithm">
                        <option value="">-- Select --</option>
                        <option value="T">T - Triple DES</option>
                        <option value="A">A - AES</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Mode of Use:</label>
                    <select id="gen_mode">
                        <option value="">-- Select --</option>
                        <option value="E">E - Encrypt</option>
                        <option value="D">D - Decrypt</option>
                        <option value="B">B - Both</option>
                        <option value="C">C - MAC</option>
                        <option value="G">G - Generate</option>
                        <option value="V">V - Verify</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Key Version:</label>
                    <input type="text" id="gen_key_version" placeholder="e.g., 00">
                </div>
                <div class="form-group">
                    <label>Exportability:</label>
                    <select id="gen_exportability">
                        <option value="S">S - Sensitive</option>
                        <option value="N">N - Not Exportable</option>
                        <option value="E">E - Exportable</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>KB Opt Date:</label>
                    <input type="text" id="gen_kb_date" placeholder="YYYYMMDD">
                </div>
                <div class="form-group">
                    <label>KB Opt Text:</label>
                    <input type="text" id="gen_kb_text" placeholder="Optional description">
                </div>
                <div class="form-group">
                    <label>KB Opt Status:</label>
                    <select id="gen_kb_status">
                        <option value="L">L - Live</option>
                        <option value="T">T - Test</option>
                    </select>
                </div>
            </div>
            
            <div class="button-group">
                <button class="btn btn-primary" onclick="addGenerateKey()">Add to Queue</button>
                <button class="btn btn-success" onclick="processGenerate()">Generate All Keys</button>
                <button class="btn btn-danger" onclick="clearGenerate()">Clear Queue</button>
            </div>
            
            <div class="form-section">
                <div class="section-title">
                    Generation Queue
                    <span class="count-badge" id="genCount">0</span>
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Description</th>
                                <th>Scheme</th>
                                <th>Usage</th>
                                <th>Algorithm</th>
                                <th>Mode</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="genTableBody"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Generation Log</div>
                <div class="log-box" id="genLogBox"></div>
            </div>
        </div>
        
        <!-- IMPORT TAB -->
        <div id="importTab" class="tab-content">
            <!-- CSV Import Section -->
            <div class="form-section" style="background: linear-gradient(135deg, #e8f5e8 0%, #d4edda 100%); border-left: 5px solid #27ae60; margin-bottom: 25px;">
                <div class="section-title" style="color: #27ae60;">📄 CSV Bulk Import - Import Jobs</div>
                <div style="display: grid; gap: 15px;">
                    <div>
                        <label style="display: block; margin-bottom: 8px; font-weight: 600;">Select CSV File:</label>
                        <input type="file" id="csvImportFile" accept=".csv" style="width: 100%; padding: 10px; border: 2px solid #27ae60; border-radius: 5px; background: white;" />
                    </div>
                    <div style="display: flex; gap: 10px; justify-content: center;">
                        <button class="btn btn-info" onclick="importCSVImport()">📥 Import CSV</button>
                        <button class="btn btn-secondary" onclick="downloadTemplateImport()">📋 Download Template</button>
                    </div>
                    <div style="font-size: 0.9em; color: #555; text-align: center;">
                        💡 Use the template to bulk-add multiple import jobs (ZMK → LMK)
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Add Single Import Job (ZMK → LMK)</div>
                <div class="form-group">
                    <label>Description*:</label>
                    <input type="text" id="imp_description" required>
                </div>
                <div class="form-group">
                    <label>ZMK Key*:</label>
                    <input type="text" id="imp_zmk_key" placeholder="Enter ZMK key" required>
                </div>
                <div class="form-group">
                    <label>Working Key (ZMK)*:</label>
                    <input type="text" id="imp_working_key" placeholder="Enter working key under ZMK" required>
                </div>
                <div class="form-group">
                    <label>Key Scheme:</label>
                    <select id="imp_key_scheme">
                        <option value="S">S - Thales KB</option>
                        <option value="R">R - TR-31</option>
                        <option value="U">U - Variant</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>LMK Identifier:</label>
                    <input type="text" id="imp_lmk_id" placeholder="e.g., 00">
                </div>
            </div>
            
            <div class="button-group">
                <button class="btn btn-primary" onclick="addImportJob()">Add to Queue</button>
                <button class="btn btn-success" onclick="processImports()">Process All Imports</button>
                <button class="btn btn-danger" onclick="clearImports()">Clear Queue</button>
            </div>
            
            <div class="form-section">
                <div class="section-title">
                    Import Queue
                    <span class="count-badge" id="impCount">0</span>
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Description</th>
                                <th>ZMK Key</th>
                                <th>Working Key</th>
                                <th>Scheme</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="impTableBody"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Import Log</div>
                <div class="log-box" id="impLogBox"></div>
            </div>
        </div>
        
        <!-- EXPORT TAB -->
        <div id="exportTab" class="tab-content">
            <!-- CSV Import Section -->
            <div class="form-section" style="background: linear-gradient(135deg, #e8f5e8 0%, #d4edda 100%); border-left: 5px solid #27ae60; margin-bottom: 25px;">
                <div class="section-title" style="color: #27ae60;">📄 CSV Bulk Import - Export Jobs</div>
                <div style="display: grid; gap: 15px;">
                    <div>
                        <label style="display: block; margin-bottom: 8px; font-weight: 600;">Select CSV File:</label>
                        <input type="file" id="csvExportFile" accept=".csv" style="width: 100%; padding: 10px; border: 2px solid #27ae60; border-radius: 5px; background: white;" />
                    </div>
                    <div style="display: flex; gap: 10px; justify-content: center;">
                        <button class="btn btn-info" onclick="importCSVExport()">📥 Import CSV</button>
                        <button class="btn btn-secondary" onclick="downloadTemplateExport()">📋 Download Template</button>
                    </div>
                    <div style="font-size: 0.9em; color: #555; text-align: center;">
                        💡 Use the template to bulk-add multiple export jobs (LMK → ZMK)
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Add Single Export Job (LMK → ZMK)</div>
                <div class="form-group">
                    <label>Description*:</label>
                    <input type="text" id="exp_description" required>
                </div>
                <div class="form-group">
                    <label>Key under LMK*:</label>
                    <input type="text" id="exp_key_lmk" placeholder="Enter key under LMK" required>
                </div>
                <div class="form-group">
                    <label>ZMK Key*:</label>
                    <input type="text" id="exp_zmk_key" placeholder="Enter ZMK key" required>
                </div>
                <div class="form-group">
                    <label>Key Scheme:</label>
                    <select id="exp_key_scheme">
                        <option value="S">S - Thales KB</option>
                        <option value="R">R - TR-31</option>
                        <option value="U">U - Variant</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>LMK Identifier:</label>
                    <input type="text" id="exp_lmk_id" placeholder="e.g., 00">
                </div>
                <div class="form-group">
                    <label>Exportability:</label>
                    <select id="exp_exportability">
                        <option value="S">S - Sensitive</option>
                        <option value="N">N - Not Exportable</option>
                        <option value="E">E - Exportable</option>
                    </select>
                </div>
            </div>
            
            <div class="button-group">
                <button class="btn btn-primary" onclick="addExportJob()">Add to Queue</button>
                <button class="btn btn-success" onclick="processExports()">Process All Exports</button>
                <button class="btn btn-danger" onclick="clearExports()">Clear Queue</button>
            </div>
            
            <div class="form-section">
                <div class="section-title">
                    Export Queue
                    <span class="count-badge" id="expCount">0</span>
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Description</th>
                                <th>Key (LMK)</th>
                                <th>ZMK Key</th>
                                <th>Scheme</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="expTableBody"></tbody>
                    </table>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Export Log</div>
                <div class="log-box" id="expLogBox"></div>
            </div>
        </div>
        
        <!-- DECODER TAB -->
        <div id="decoderTab" class="tab-content">
            <div class="form-section">
                <div class="section-title">TR-31/X9.143 & Thales Key Block Parser</div>
                <div class="form-group">
                    <label>Key Block:</label>
                    <textarea class="decoder-input" id="decoder_input" placeholder="Paste key block here (R=TR-31, V=GISKE, S=Thales)..."></textarea>
                </div>
            </div>
            
            <div class="button-group">
                <button class="btn btn-primary" onclick="parseKeyBlock()">Parse Key Block</button>
                <button class="btn btn-secondary" onclick="clearDecoder()">Clear</button>
            </div>
            
            <div class="form-section">
                <div class="section-title">Analysis Output</div>
                <div class="decoder-output" id="decoder_output">Awaiting key block input...</div>
            </div>
        </div>
        
        <!-- MONITORING TAB -->
        <div id="monitoringTab" class="tab-content">
            <div class="form-section">
                <div class="section-title">📊 HSM Performance Monitoring</div>
                <div class="button-group">
                    <button class="btn btn-primary" onclick="refreshHSMLoading()">🔄 Refresh HSM Loading (J2)</button>
                    <button class="btn btn-primary" onclick="refreshCommandVolumes()">🔄 Refresh Command Volumes (J4)</button>
                </div>
            </div>
            
            <!-- HSM Loading Section -->
            <div class="form-section">
                <div class="section-title">HSM CPU Loading Distribution</div>
                <div class="monitor-info" id="loadingInfo"></div>
                <div class="chart-container">
                    <div class="chart-wrapper">
                        <canvas id="loadingChart"></canvas>
                    </div>
                </div>
            </div>
            
            <!-- Command Volumes Section -->
            <div class="form-section">
                <div class="section-title">Host Command Volumes (Top 20)</div>
                <div class="monitor-info" id="volumesInfo"></div>
                <div class="chart-container">
                    <div class="chart-wrapper">
                        <canvas id="volumesChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="form-section">
                <div class="section-title">Monitoring Log</div>
                <div class="log-box" id="monitorLogBox"></div>
            </div>
        </div>
        
        <!-- CONFIG TAB -->
        <div id="configTab" class="tab-content">
            <div class="form-section">
                <div class="section-title">HSM Connection Settings</div>
                <div class="form-group">
                    <label>HSM IP Address*:</label>
                    <input type="text" id="config_hsm_ip" required>
                </div>
                <div class="form-group">
                    <label>HSM Port:</label>
                    <input type="number" id="config_hsm_port" value="1500">
                </div>
                <div class="form-group">
                    <label>Output Directory:</label>
                    <input type="text" id="config_output_path" placeholder="~/hsm_output">
                </div>
                <div class="form-group">
                    <label>Debug Mode:</label>
                    <input type="checkbox" id="config_debug_mode" checked>
                </div>
            </div>
            
            <div class="button-group">
                <button class="btn btn-success" onclick="saveConfig()">Save Configuration</button>
                <button class="btn btn-info" onclick="testConnection()">Test Connection</button>
            </div>
            
            <div class="form-section">
                <div class="section-title">Configuration Status</div>
                <div class="log-box" id="configLogBox"></div>
            </div>
        </div>
    </div>

    <script>
        // Global chart instances
        let loadingChart = null;
        let volumesChart = null;
        
        // Tab switching
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            
            const tabs = {
                'generate': [0, 'generateTab'],
                'import': [1, 'importTab'],
                'export': [2, 'exportTab'],
                'decoder': [3, 'decoderTab'],
                'monitoring': [4, 'monitoringTab'],
                'config': [5, 'configTab']
            };
            
            if (tabs[tab]) {
                document.querySelectorAll('.tab')[tabs[tab][0]].classList.add('active');
                document.getElementById(tabs[tab][1]).classList.add('active');
                
                if (tab === 'config') loadConfig();
            }
        }
        
        // =============== GENERATE FUNCTIONS ===============
        function addGenerateKey() {
            const data = {
                cb_description: document.getElementById('gen_description').value,
                key_scheme: document.getElementById('gen_key_scheme').value,
                lmk_identifier: document.getElementById('gen_lmk_id').value,
                key_usage: document.getElementById('gen_key_usage').value,
                algorithm: document.getElementById('gen_algorithm').value,
                mode_of_use: document.getElementById('gen_mode').value,
                key_version_number: document.getElementById('gen_key_version').value,
                exportability: document.getElementById('gen_exportability').value,
                kb_opt_date: document.getElementById('gen_kb_date').value,
                kb_opt_text: document.getElementById('gen_kb_text').value,
                kb_opt_idx: '',
                kb_opt_shared: 'N',
                kb_opt_status: document.getElementById('gen_kb_status').value
            };
            
            if (!data.cb_description || !data.key_usage) {
                alert('Description and Key Usage are required!');
                return;
            }
            
            fetch('/api/add_generate_key', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    loadGenerateKeys();
                    logGen('Added: ' + data.cb_description, 'status-success');
                }
            });
        }
        
        function processGenerate() {
            if (!confirm('Generate all keys? This will communicate with the HSM.')) return;
            
            logGen('Starting generation...', 'status-info');
            fetch('/api/process_generate', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    d.results.forEach(r => {
                        const cls = 'status-' + r.status;
                        logGen(`${r.status.toUpperCase()}: ${r.key}: ${r.message}${r.kcv ? ' (KCV: ' + r.kcv + ')' : ''}`, cls);
                    });
                }
            });
        }
        
        function clearGenerate() {
            if (!confirm('Clear all generation jobs?')) return;
            fetch('/api/clear_generate', {method: 'POST'})
            .then(() => {
                loadGenerateKeys();
                logGen('Queue cleared', 'status-info');
            });
        }
        
        function loadGenerateKeys() {
            fetch('/api/generate_keys')
            .then(r => r.json())
            .then(keys => {
                const tbody = document.getElementById('genTableBody');
                tbody.innerHTML = '';
                keys.forEach((k, i) => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${k.cb_description}</td>
                        <td>${k.key_scheme}</td>
                        <td>${k.key_usage}</td>
                        <td>${k.algorithm}</td>
                        <td>${k.mode_of_use}</td>
                        <td><button class="btn btn-danger" onclick="deleteGenKey(${i})">Delete</button></td>
                    `;
                });
                document.getElementById('genCount').textContent = keys.length;
            });
        }
        
        function deleteGenKey(idx) {
            fetch('/api/generate_keys', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({index: idx})
            })
            .then(() => loadGenerateKeys());
        }
        
        function logGen(msg, cls = '') {
            const box = document.getElementById('genLogBox');
            const div = document.createElement('div');
            div.className = cls;
            div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }
        
        // CSV functions for Generate
        function downloadTemplateGenerate() {
            window.open('/api/template/generate', '_blank');
            logGen('CSV template download started');
        }
        
        function importCSVGenerate() {
            const fileInput = document.getElementById('csvGenerateFile');
            const file = fileInput.files[0];
            
            if (!file) {
                alert('Please select a CSV file!');
                return;
            }
            
            const formData = new FormData();
            formData.append('csvFile', file);
            
            logGen('Importing CSV: ' + file.name);
            
            fetch('/api/import_csv_generate', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    logGen(`Imported ${d.count} keys from ${file.name}`, 'status-success');
                    loadGenerateKeys();
                    fileInput.value = '';
                } else {
                    logGen(`Import failed: ${d.error}`, 'status-error');
                    alert('Import failed: ' + d.error);
                }
            })
            .catch(error => {
                logGen(`Import error: ${error.message}`, 'status-error');
                alert('Import error: ' + error.message);
            });
        }
        
        // =============== IMPORT FUNCTIONS ===============
        function addImportJob() {
            const data = {
                cb_description: document.getElementById('imp_description').value,
                zmk_key: document.getElementById('imp_zmk_key').value,
                working_key: document.getElementById('imp_working_key').value,
                key_scheme: document.getElementById('imp_key_scheme').value,
                lmk_identifier: document.getElementById('imp_lmk_id').value
            };
            
            if (!data.zmk_key || !data.working_key) {
                alert('ZMK Key and Working Key are required!');
                return;
            }
            
            fetch('/api/add_import_job', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    loadImportJobs();
                    logImp('Added: ' + data.cb_description, 'status-success');
                }
            });
        }
        
        function processImports() {
            if (!confirm('Process all import jobs?')) return;
            
            logImp('Starting imports...', 'status-info');
            fetch('/api/process_imports', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    d.results.forEach(r => {
                        const cls = 'status-' + r.status;
                        logImp(`${r.status.toUpperCase()}: ${r.job}: ${r.message}${r.kcv ? ' (KCV: ' + r.kcv + ')' : ''}`, cls);
                    });
                }
            });
        }
        
        function clearImports() {
            if (!confirm('Clear all import jobs?')) return;
            fetch('/api/clear_imports', {method: 'POST'})
            .then(() => {
                loadImportJobs();
                logImp('Queue cleared', 'status-info');
            });
        }
        
        function loadImportJobs() {
            fetch('/api/import_jobs')
            .then(r => r.json())
            .then(jobs => {
                const tbody = document.getElementById('impTableBody');
                tbody.innerHTML = '';
                jobs.forEach((j, i) => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${j.cb_description}</td>
                        <td>${j.zmk_key.substring(0, 20)}...</td>
                        <td>${j.working_key.substring(0, 20)}...</td>
                        <td>${j.key_scheme}</td>
                        <td><button class="btn btn-danger" onclick="deleteImpJob(${i})">Delete</button></td>
                    `;
                });
                document.getElementById('impCount').textContent = jobs.length;
            });
        }
        
        function deleteImpJob(idx) {
            fetch('/api/import_jobs', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({index: idx})
            })
            .then(() => loadImportJobs());
        }
        
        function logImp(msg, cls = '') {
            const box = document.getElementById('impLogBox');
            const div = document.createElement('div');
            div.className = cls;
            div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }
        
        // CSV functions for Import
        function downloadTemplateImport() {
            window.open('/api/template/import', '_blank');
            logImp('CSV template download started');
        }
        
        function importCSVImport() {
            const fileInput = document.getElementById('csvImportFile');
            const file = fileInput.files[0];
            
            if (!file) {
                alert('Please select a CSV file!');
                return;
            }
            
            const formData = new FormData();
            formData.append('csvFile', file);
            
            logImp('Importing CSV: ' + file.name);
            
            fetch('/api/import_csv_import', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    logImp(`Imported ${d.count} jobs from ${file.name}`, 'status-success');
                    loadImportJobs();
                    fileInput.value = '';
                } else {
                    logImp(`Import failed: ${d.error}`, 'status-error');
                    alert('Import failed: ' + d.error);
                }
            })
            .catch(error => {
                logImp(`Import error: ${error.message}`, 'status-error');
                alert('Import error: ' + error.message);
            });
        }
        
        // =============== EXPORT FUNCTIONS ===============
        function addExportJob() {
            const data = {
                cb_description: document.getElementById('exp_description').value,
                key_under_lmk: document.getElementById('exp_key_lmk').value,
                zmk_key: document.getElementById('exp_zmk_key').value,
                key_scheme: document.getElementById('exp_key_scheme').value,
                lmk_identifier: document.getElementById('exp_lmk_id').value,
                exportability: document.getElementById('exp_exportability').value
            };
            
            if (!data.key_under_lmk || !data.zmk_key) {
                alert('Key under LMK and ZMK Key are required!');
                return;
            }
            
            fetch('/api/add_export_job', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    loadExportJobs();
                    logExp('Added: ' + data.cb_description, 'status-success');
                }
            });
        }
        
        function processExports() {
            if (!confirm('Process all export jobs?')) return;
            
            logExp('Starting exports...', 'status-info');
            fetch('/api/process_exports', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    d.results.forEach(r => {
                        const cls = 'status-' + r.status;
                        logExp(`${r.status.toUpperCase()}: ${r.job}: ${r.message}${r.kcv ? ' (KCV: ' + r.kcv + ')' : ''}`, cls);
                    });
                }
            });
        }
        
        function clearExports() {
            if (!confirm('Clear all export jobs?')) return;
            fetch('/api/clear_exports', {method: 'POST'})
            .then(() => {
                loadExportJobs();
                logExp('Queue cleared', 'status-info');
            });
        }
        
        function loadExportJobs() {
            fetch('/api/export_jobs')
            .then(r => r.json())
            .then(jobs => {
                const tbody = document.getElementById('expTableBody');
                tbody.innerHTML = '';
                jobs.forEach((j, i) => {
                    const row = tbody.insertRow();
                    row.innerHTML = `
                        <td>${j.cb_description}</td>
                        <td>${j.key_under_lmk.substring(0, 20)}...</td>
                        <td>${j.zmk_key.substring(0, 20)}...</td>
                        <td>${j.key_scheme}</td>
                        <td><button class="btn btn-danger" onclick="deleteExpJob(${i})">Delete</button></td>
                    `;
                });
                document.getElementById('expCount').textContent = jobs.length;
            });
        }
        
        function deleteExpJob(idx) {
            fetch('/api/export_jobs', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({index: idx})
            })
            .then(() => loadExportJobs());
        }
        
        function logExp(msg, cls = '') {
            const box = document.getElementById('expLogBox');
            const div = document.createElement('div');
            div.className = cls;
            div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }
        
        // CSV functions for Export
        function downloadTemplateExport() {
            window.open('/api/template/export', '_blank');
            logExp('CSV template download started');
        }
        
        function importCSVExport() {
            const fileInput = document.getElementById('csvExportFile');
            const file = fileInput.files[0];
            
            if (!file) {
                alert('Please select a CSV file!');
                return;
            }
            
            const formData = new FormData();
            formData.append('csvFile', file);
            
            logExp('Importing CSV: ' + file.name);
            
            fetch('/api/import_csv_export', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    logExp(`Imported ${d.count} jobs from ${file.name}`, 'status-success');
                    loadExportJobs();
                    fileInput.value = '';
                } else {
                    logExp(`Import failed: ${d.error}`, 'status-error');
                    alert('Import failed: ' + d.error);
                }
            })
            .catch(error => {
                logExp(`Import error: ${error.message}`, 'status-error');
                alert('Import error: ' + error.message);
            });
        }
        
        // =============== DECODER FUNCTIONS ===============
        function parseKeyBlock() {
            const input = document.getElementById('decoder_input').value.trim();
            if (!input) {
                alert('Please enter a key block!');
                return;
            }
            
            fetch('/api/parse_keyblock', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key_block: input})
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    displayDecoderOutput(d.result);
                } else {
                    document.getElementById('decoder_output').textContent = 'ERROR: ' + d.error;
                }
            });
        }
        
        function displayDecoderOutput(result) {
            let output = '═'.repeat(80) + '\\n';
            output += '               KEY BLOCK ANALYSIS\\n';
            output += '═'.repeat(80) + '\\n\\n';
            
            result.analysis.forEach(line => {
                output += line + '\\n';
            });
            
            output += '\\n' + '─'.repeat(80) + '\\n';
            output += 'HEADER (16 bytes)\\n';
            output += '─'.repeat(80) + '\\n';
            const h = result.header;
            output += `Version:       ${h.version_id}\\n`;
            output += `Length:        ${h.key_block_length} bytes\\n`;
            output += `Key Usage:     ${h.key_usage}\\n`;
            output += `Algorithm:     ${h.algorithm}\\n`;
            output += `Mode:          ${h.mode_of_use}\\n`;
            output += `Exportability: ${h.exportability}\\n`;
            output += `Opt Blocks:    ${h.num_optional_blocks}\\n`;
            
            if (result.optional_blocks.length > 0) {
                output += '\\n' + '─'.repeat(80) + '\\n';
                output += `OPTIONAL BLOCKS (${result.optional_blocks.length})\\n`;
                output += '─'.repeat(80) + '\\n';
                result.optional_blocks.forEach((b, i) => {
                    output += `Block ${i+1}: ${b.id} (${b.length} bytes)\\n`;
                    output += `  Data: ${b.data}\\n`;
                });
            }
            
            output += '\\n' + '─'.repeat(80) + '\\n';
            output += 'ENCRYPTED KEY DATA\\n';
            output += '─'.repeat(80) + '\\n';
            output += result.encrypted_key_data + '\\n';
            
            output += '\\n' + '─'.repeat(80) + '\\n';
            output += 'AUTHENTICATOR\\n';
            output += '─'.repeat(80) + '\\n';
            output += result.authenticator + '\\n';
            
            output += '\\n' + '═'.repeat(80);
            
            document.getElementById('decoder_output').textContent = output;
        }
        
        function clearDecoder() {
            document.getElementById('decoder_input').value = '';
            document.getElementById('decoder_output').textContent = 'Awaiting key block input...';
        }
        
        // =============== MONITORING FUNCTIONS ===============
        function refreshHSMLoading() {
            logMonitor('Fetching HSM loading data...', 'status-info');
            
            fetch('/api/get_hsm_loading', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    displayHSMLoading(d.data);
                    logMonitor('HSM loading data refreshed successfully', 'status-success');
                } else {
                    logMonitor('Error: ' + d.error, 'status-error');
                    alert('Error fetching HSM loading: ' + d.error);
                }
            })
            .catch(error => {
                logMonitor('Error: ' + error.message, 'status-error');
                alert('Error: ' + error.message);
            });
        }
        
        function displayHSMLoading(data) {
            // Display info cards
            const infoHtml = `
                <div class="info-card">
                    <div class="label">Serial Number</div>
                    <div class="value">${data.serial_number}</div>
                </div>
                <div class="info-card">
                    <div class="label">Monitoring Period</div>
                    <div class="value">${formatSeconds(data.seconds)}</div>
                </div>
                <div class="info-card">
                    <div class="label">Start Date/Time</div>
                    <div class="value">${formatDate(data.start_date)} ${formatTime(data.start_time)}</div>
                </div>
                <div class="info-card">
                    <div class="label">Status</div>
                    <div class="value">${data.is_active ? 'Active' : 'Paused'}</div>
                </div>
            `;
            document.getElementById('loadingInfo').innerHTML = infoHtml;
            
            // Prepare chart data
            const labels = data.loading_ranges.map(r => `${r.start_percentage}-${r.end_percentage}%`);
            const values = data.loading_ranges.map(r => r.time_periods);
            
            // Destroy existing chart if it exists
            if (loadingChart) {
                loadingChart.destroy();
            }
            
            // Create new chart
            const ctx = document.getElementById('loadingChart').getContext('2d');
            loadingChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Time Periods',
                        data: values,
                        backgroundColor: 'rgba(102, 126, 234, 0.8)',
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'HSM CPU Loading Distribution',
                            font: { size: 18, weight: 'bold' }
                        },
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return `Time Periods: ${context.parsed.y.toLocaleString()}`;
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Time Periods'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'CPU Loading Range'
                            }
                        }
                        }
                }
            });
        }
        
        function refreshCommandVolumes() {
            logMonitor('Fetching command volumes data...', 'status-info');
            
            fetch('/api/get_command_volumes', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    displayCommandVolumes(d.data);
                    logMonitor('Command volumes data refreshed successfully', 'status-success');
                } else {
                    logMonitor('Error: ' + d.error, 'status-error');
                    alert('Error fetching command volumes: ' + d.error);
                }
            })
            .catch(error => {
                logMonitor('Error: ' + error.message, 'status-error');
                alert('Error: ' + error.message);
            });
        }
        
        function displayCommandVolumes(data) {
        // Filtra il comando NO
        const filteredVolumes = data.command_volumes.filter(c => c.command_code !== 'NO');
        
        // Calcola totale transazioni (incluso NO per la percentuale)
        const totalTransactions = data.command_volumes.reduce((sum, cmd) => sum + cmd.transactions, 0);
        
        // Trova il comando NO per mostrarlo separatamente
        const noCommand = data.command_volumes.find(c => c.command_code === 'NO');
        
        // Display info cards
        let infoHtml = `
            <div class="info-card">
                <div class="label">Serial Number</div>
                <div class="value">${data.serial_number}</div>
            </div>
            <div class="info-card">
                <div class="label">Total Transactions</div>
                <div class="value">${totalTransactions.toLocaleString()}</div>
            </div>
            <div class="info-card">
                <div class="label">Monitoring Period</div>
                <div class="value">${formatSeconds(data.seconds)}</div>
            </div>
        `;
    
        // Aggiungi card per comando NO se esiste
        if (noCommand) {
            const noPercentage = ((noCommand.transactions / totalTransactions) * 100).toFixed(2);
            infoHtml += `
                <div class="info-card" style="background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);">
                    <div class="label">Command NO (Excluded)</div>
                    <div class="value">${noCommand.transactions.toLocaleString()} (${noPercentage}%)</div>
                </div>
            `;
        }
    
        infoHtml += `
            <div class="info-card">
                <div class="label">Commands Tracked</div>
                <div class="value">${filteredVolumes.length}</div>
            </div>
        `;
    
        document.getElementById('volumesInfo').innerHTML = infoHtml;
        
        // Get top 20 commands (escluso NO)
        const top20 = filteredVolumes.slice(0, 20);
        const labels = top20.map(c => c.command_code);
        const values = top20.map(c => c.transactions);
        
        // Destroy existing chart if it exists
        if (volumesChart) {
            volumesChart.destroy();
        }
    
        // Create new chart
        const ctx = document.getElementById('volumesChart').getContext('2d');
        volumesChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Transactions',
                    data: values,
                    backgroundColor: 'rgba(56, 239, 125, 0.8)',
                    borderColor: 'rgba(17, 153, 142, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    title: {
                        display: true,
                        text: 'Top 20 HSM Commands by Volume (NO excluded)',
                        font: { size: 18, weight: 'bold' }
                    },
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const percentage = ((context.parsed.x / totalTransactions) * 100).toFixed(2);
                                return `Transactions: ${context.parsed.x.toLocaleString()} (${percentage}%)`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Transactions'
                        },
                        ticks: {
                            callback: function(value) {
                                return value.toLocaleString();
                            }
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Command Code'
                        }
                    }
                }
            }
        });
    }
        
        function formatDate(dateStr) {
            // Format: YYMMDD to DD/MM/YY
            if (dateStr.length === 6) {
                return `${dateStr.substr(4,2)}/${dateStr.substr(2,2)}/${dateStr.substr(0,2)}`;
            }
            return dateStr;
        }
        
        function formatTime(timeStr) {
            // Format: HHMMSS to HH:MM:SS
            if (timeStr.length === 6) {
                return `${timeStr.substr(0,2)}:${timeStr.substr(2,2)}:${timeStr.substr(4,2)}`;
            }
            return timeStr;
        }
        
        function formatSeconds(seconds) {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            
            let result = [];
            if (days > 0) result.push(`${days}d`);
            if (hours > 0) result.push(`${hours}h`);
            if (minutes > 0) result.push(`${minutes}m`);
            if (secs > 0 || result.length === 0) result.push(`${secs}s`);
            
            return result.join(' ');
        }
        
        function logMonitor(msg, cls = '') {
            const box = document.getElementById('monitorLogBox');
            const div = document.createElement('div');
            div.className = cls;
            div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }
        
        // =============== CONFIG FUNCTIONS ===============
        function loadConfig() {
            fetch('/api/config')
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    document.getElementById('config_hsm_ip').value = d.hsm_ip;
                    document.getElementById('config_hsm_port').value = d.hsm_port;
                    document.getElementById('config_output_path').value = d.output_path;
                    document.getElementById('config_debug_mode').checked = d.debug_mode;
                    logConfig(`Current HSM: ${d.hsm_ip}:${d.hsm_port}`, 'status-info');
                }
            });
        }
        
        function saveConfig() {
            const config = {
                hsm_ip: document.getElementById('config_hsm_ip').value,
                hsm_port: document.getElementById('config_hsm_port').value,
                output_path: document.getElementById('config_output_path').value,
                debug_mode: document.getElementById('config_debug_mode').checked
            };
            
            fetch('/api/set_config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            })
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    logConfig('Configuration saved successfully!', 'status-success');
                } else {
                    logConfig('Error: ' + d.error, 'status-error');
                }
            });
        }
        
        function testConnection() {
            logConfig('Testing HSM connection...', 'status-info');
            
            // Try to fetch HSM loading as a connection test
            fetch('/api/get_hsm_loading', {method: 'POST'})
            .then(r => r.json())
            .then(d => {
                if (d.success) {
                    logConfig(`✓ Connection successful! HSM SN: ${d.data.serial_number}`, 'status-success');
                } else {
                    logConfig(`✗ Connection failed: ${d.error}`, 'status-error');
                }
            })
            .catch(error => {
                logConfig(`✗ Connection error: ${error.message}`, 'status-error');
            });
        }
        
        function logConfig(msg, cls = '') {
            const box = document.getElementById('configLogBox');
            const div = document.createElement('div');
            div.className = cls;
            div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }
        
        // Initialize on load
        loadGenerateKeys();
        loadImportJobs();
        loadExportJobs();
        logGen('HSM Complete Manager v2.1 ready', 'status-success');
    </script>
</body>
</html>
        '''
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    # API endpoint implementations
    def serve_generate_keys(self):
        self.send_json_response(hsm_manager.generate_keys)
    
    def serve_import_jobs(self):
        self.send_json_response(hsm_manager.import_jobs)
    
    def serve_export_jobs(self):
        self.send_json_response(hsm_manager.export_jobs)
    
    def get_config(self):
        config = {
            'success': True,
            'hsm_ip': hsm_manager.hsm_ip,
            'hsm_port': hsm_manager.hsm_port,
            'output_path': hsm_manager.output_path,
            'debug_mode': hsm_manager.debug_mode
        }
        self.send_json_response(config)
    
    def set_config(self):
        data = self.read_json_body()
        try:
            if data.get('hsm_ip'):
                hsm_manager.hsm_ip = data['hsm_ip'].strip()
            if data.get('hsm_port'):
                hsm_manager.hsm_port = int(data['hsm_port'])
            if data.get('output_path'):
                hsm_manager.output_path = os.path.expanduser(data['output_path'].strip())
            hsm_manager.debug_mode = data.get('debug_mode', True)
            
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def add_generate_key(self):
        data = self.read_json_body()
        try:
            hsm_manager.generate_keys.append(data)
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def process_generate(self):
        try:
            results = hsm_manager.process_all_generate_keys()
            self.send_json_response({'success': True, 'results': results})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def clear_generate(self):
        hsm_manager.generate_keys.clear()
        self.send_json_response({'success': True})
    
    def add_import_job(self):
        data = self.read_json_body()
        try:
            hsm_manager.import_jobs.append(data)
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def process_imports(self):
        try:
            results = hsm_manager.process_all_imports()
            self.send_json_response({'success': True, 'results': results})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def clear_imports(self):
        hsm_manager.import_jobs.clear()
        self.send_json_response({'success': True})
    
    def add_export_job(self):
        data = self.read_json_body()
        try:
            hsm_manager.export_jobs.append(data)
            self.send_json_response({'success': True})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def process_exports(self):
        try:
            results = hsm_manager.process_all_exports()
            self.send_json_response({'success': True, 'results': results})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def clear_exports(self):
        hsm_manager.export_jobs.clear()
        self.send_json_response({'success': True})
    
    def parse_keyblock(self):
        data = self.read_json_body()
        try:
            key_block = data.get('key_block', '')
            result = hsm_manager.parse_key_block(key_block)
            self.send_json_response({'success': True, 'result': result})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    # Monitoring endpoints
    def get_hsm_loading(self):
        try:
            data = hsm_manager.get_hsm_loading()
            self.send_json_response({'success': True, 'data': data})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    def get_command_volumes(self):
        try:
            data = hsm_manager.get_command_volumes()
            self.send_json_response({'success': True, 'data': data})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)})
    
    # CSV Template Downloads
    def download_template_generate(self):
        try:
            template_csv = hsm_manager.export_template_generate_csv()
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="hsm_generate_template.csv"')
            self.end_headers()
            self.wfile.write(template_csv.encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")
    
    def download_template_import(self):
        try:
            template_csv = hsm_manager.export_template_import_csv()
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="hsm_import_template.csv"')
            self.end_headers()
            self.wfile.write(template_csv.encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")
    
    def download_template_export(self):
        try:
            template_csv = hsm_manager.export_template_export_csv()
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv')
            self.send_header('Content-Disposition', 'attachment; filename="hsm_export_template.csv"')
            self.end_headers()
            self.wfile.write(template_csv.encode('utf-8'))
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")
    
    # CSV Imports
    def import_csv_generate(self):
        try:
            csv_content = self.parse_multipart_csv()
            if not csv_content:
                raise ValueError("No CSV content found")
            
            result = hsm_manager.import_csv_generate(csv_content)
            
            if result['success']:
                hsm_manager.generate_keys.extend(result['keys'])
                response = {
                    'success': True,
                    'message': f"Imported {result['count']} keys",
                    'count': result['count']
                }
            else:
                response = {'success': False, 'error': result['error']}
        except Exception as e:
            response = {'success': False, 'error': str(e)}
        
        self.send_json_response(response)
    
    def import_csv_import(self):
        try:
            csv_content = self.parse_multipart_csv()
            if not csv_content:
                raise ValueError("No CSV content found")
            
            result = hsm_manager.import_csv_for_import(csv_content)
            
            if result['success']:
                hsm_manager.import_jobs.extend(result['jobs'])
                response = {
                    'success': True,
                    'message': f"Imported {result['count']} jobs",
                    'count': result['count']
                }
            else:
                response = {'success': False, 'error': result['error']}
        except Exception as e:
            response = {'success': False, 'error': str(e)}
        
        self.send_json_response(response)
    
    def import_csv_export(self):
        try:
            csv_content = self.parse_multipart_csv()
            if not csv_content:
                raise ValueError("No CSV content found")
            
            result = hsm_manager.import_csv_for_export(csv_content)
            
            if result['success']:
                hsm_manager.export_jobs.extend(result['jobs'])
                response = {
                    'success': True,
                    'message': f"Imported {result['count']} jobs",
                    'count': result['count']
                }
            else:
                response = {'success': False, 'error': result['error']}
        except Exception as e:
            response = {'success': False, 'error': str(e)}
        
        self.send_json_response(response)
    
    def parse_multipart_csv(self):
        """Parse multipart form data to extract CSV content"""
        content_type = self.headers.get('Content-Type', '')
        if not content_type.startswith('multipart/form-data'):
            raise ValueError("Expected multipart/form-data")
        
        boundary_parts = content_type.split('boundary=')
        if len(boundary_parts) < 2:
            raise ValueError("No boundary found")
        boundary = boundary_parts[1].strip().strip('"')
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        boundary_bytes = f'--{boundary}'.encode()
        parts = post_data.split(boundary_bytes)
        
        for part in parts:
            if b'Content-Disposition: form-data; name="csvFile"' in part:
                header_end = part.find(b'\r\n\r\n')
                if header_end == -1:
                    header_end = part.find(b'\n\n')
                    if header_end != -1:
                        header_end += 2
                else:
                    header_end += 4
                
                if header_end != -1:
                    content = part[header_end:].rstrip(b'\r\n-')
                    try:
                        return content.decode('utf-8')
                    except UnicodeDecodeError:
                        return content.decode('utf-8', errors='ignore')
        
        return None
    
    # Helper methods
    def read_json_body(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        return json.loads(post_data.decode())
    
    def send_json_response(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def log_message(self, format, *args):
        pass


def start_server(port=8080):
    """Start the unified HSM server"""
    server = HTTPServer(('localhost', port), UnifiedRequestHandler)
    print(f"HSM Complete Manager v{HSMManager().VERSION}")
    print(f"Server running at http://localhost:{port}")
    print("Opening browser...")
    
    def open_browser():
        time.sleep(1)
        webbrowser.open(f'http://localhost:{port}')
    
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.shutdown()


if __name__ == "__main__":
    start_server()