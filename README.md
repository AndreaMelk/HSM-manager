# HSM Manager - GUI for PayShield

Unified tool for PayShield HSM management with web interface.

## Initial Setup

### 1. Clone the repository
```bash
git clone https://github.com/AndreaMelk/HSM-manager.git
cd hsm_manager
```

### 2. Create configuration file

Copy the example file and modify with your data:

```bash
cp hsm_config.example.json hsm_config.json
```

Edit `hsm_config.json` with your HSM parameters:

```json
{
  "hsm_ip": "192.168.1.100",
  "hsm_port": 1500,
  "output_path": "~/hsm_output",
  "debug_mode": false
}
```

**Parameters:**
- `hsm_ip`: IP address of your PayShield HSM
- `hsm_port`: Communication port (default: 1500)
- `output_path`: Directory for output files
- `debug_mode`: Enable detailed logging (true/false)

### 3. Install dependencies

This tool uses only Python standard libraries, no additional dependencies required.

### 4. Start the server

```bash
python3 HSM-manager.py
```

The server will start on `http://localhost:8080` and automatically open your browser.

## Features

### Key Generation
- Cryptographic key generation
- Support for various algorithms (AES, DES, TDES)
- Flexible key parameter configuration
- CSV Import/Export

### Key Import/Export
- Import existing keys
- Export keys in TR-31 format
- Key Block management
- Batch operations support

### Key Block Analysis
- TR-31/X9.143 Key Block parser
- Detailed component analysis
- Header and optional blocks visualization

### HSM Monitoring
- Real-time HSM load monitoring
- Command execution statistics
- Status dashboard

## Security Considerations

1. **Configuration file**: The `hsm_config.json` file contains sensitive information and MUST NOT be shared
2. **Debug mode**: In production, keep `debug_mode: false`
3. **Output files**: Generated files may contain sensitive cryptographic material
4. **HSM access**: Ensure only authorized users can run this tool
5. **Network**: This tool connects directly to the HSM, verify network policies

## File Structure

```
hsm_manager/
├── HSM-manager.py              # Main script
├── hsm_config.example.json     # Configuration template (commit this)
├── hsm_config.json             # Real configuration (DO NOT commit)
├── .gitignore                  # Excludes sensitive files
└── README.md                   # This file
```

## Requirements

- Python 3.6+
- Network access to PayShield HSM
- Operating System: Linux/macOS/Windows

## CSV Templates

The tool includes CSV templates for:
- Key generation: `Download Template` in Key Generation section
- Key import: `Download Template` in Key Import section
- Key export: `Download Template` in Key Export section

## Advanced Configuration

### Custom Port
To use a different port than 8080:

```python
# Modify the last line in HSM-manager.py
if __name__ == "__main__":
    start_server(8081)  # Use port 8081
```

### Custom Output Path
Modify `output_path` in `hsm_config.json` to change the output directory.

## Troubleshooting

### Error "Configuration file not found"
Make sure you created `hsm_config.json` from `hsm_config.example.json`.

### HSM connection error
Verify:
- HSM IP and port in configuration file
- Network connectivity to the HSM
- Firewall and security rules

### Browser doesn't open automatically
Open manually: `http://localhost:8080`


**Version:** 2.1.0.0
