# HSM Manager - GUI per PayShield

Tool unificato per la gestione di HSM PayShield con interfaccia web.

## ⚠️ IMPORTANTE - SICUREZZA

**NON committare mai il file `hsm_config.json` su Git!**

Questo file contiene informazioni sensibili sulla configurazione HSM (indirizzi IP, porte, ecc.) e **DEVE** rimanere locale.

## 🚀 Setup Iniziale

### 1. Clona il repository
```bash
git clone <your-repo-url>
cd hsm_manager
```

### 2. Crea il file di configurazione

Copia il file di esempio e modifica con i tuoi dati:

```bash
cp hsm_config.example.json hsm_config.json
```

Modifica `hsm_config.json` con i parametri del tuo HSM:

```json
{
  "hsm_ip": "192.168.1.100",
  "hsm_port": 1500,
  "output_path": "~/hsm_output",
  "debug_mode": false
}
```

**Parametri:**
- `hsm_ip`: Indirizzo IP del tuo HSM PayShield
- `hsm_port`: Porta di comunicazione (default: 1500)
- `output_path`: Directory per i file di output
- `debug_mode`: Abilita logging dettagliato (true/false)

### 3. Installa le dipendenze

Questo tool usa solo librerie Python standard, non sono necessarie dipendenze aggiuntive.

### 4. Avvia il server

```bash
python3 HSM-manager.py
```

Il server si avvierà su `http://localhost:8080` e aprirà automaticamente il browser.

## 📋 Funzionalità

### Key Generation
- Generazione di chiavi crittografiche
- Supporto per vari algoritmi (AES, DES, TDES)
- Configurazione flessibile dei parametri delle chiavi
- Import/Export da file CSV

### Key Import/Export
- Import di chiavi esistenti
- Export di chiavi in formato TR-31
- Gestione Key Blocks
- Supporto per multiple operazioni batch

### Key Block Analysis
- Parser per Key Blocks TR-31/X9.143
- Analisi dettagliata dei componenti
- Visualizzazione header e optional blocks

### HSM Monitoring
- Monitoraggio carico HSM in tempo reale
- Statistiche comandi eseguiti
- Dashboard di stato

## 🔒 Considerazioni di Sicurezza

1. **File di configurazione**: Il file `hsm_config.json` contiene informazioni sensibili e NON deve essere condiviso
2. **Debug mode**: In produzione, mantenere `debug_mode: false`
3. **Output files**: I file generati potrebbero contenere materiale crittografico sensibile
4. **Accesso HSM**: Assicurarsi che solo utenti autorizzati possano eseguire questo tool
5. **Network**: Il tool si connette direttamente all'HSM, verificare le policy di rete

## 📁 Struttura File

```
hsm_manager/
├── HSM-manager.py              # Script principale
├── hsm_config.example.json     # Template configurazione (da committare)
├── hsm_config.json             # Configurazione reale (NON committare)
├── .gitignore                  # Esclude file sensibili
└── README.md                   # Questo file
```

## 🛠️ Requisiti

- Python 3.6+
- Accesso di rete all'HSM PayShield
- Sistema operativo: Linux/macOS/Windows

## 📝 Template CSV

Il tool include template CSV per:
- Generazione chiavi: `Download Template` nella sezione Key Generation
- Import chiavi: `Download Template` nella sezione Key Import
- Export chiavi: `Download Template` nella sezione Key Export

## ⚙️ Configurazione Avanzata

### Custom Port
Per usare una porta diversa dalla 8080:

```python
# Modifica l'ultima riga in HSM-manager.py
if __name__ == "__main__":
    start_server(8081)  # Usa la porta 8081
```

### Output Path Personalizzato
Modifica `output_path` in `hsm_config.json` per cambiare la directory di output.

## 🐛 Troubleshooting

### Errore "Configuration file not found"
Assicurati di aver creato `hsm_config.json` da `hsm_config.example.json`.

### Errore di connessione HSM
Verifica:
- IP e porta dell'HSM nel file di configurazione
- Connettività di rete verso l'HSM
- Firewall e regole di sicurezza

### Il browser non si apre automaticamente
Apri manualmente: `http://localhost:8080`

## 📄 Licenza

[Specificare la licenza appropriata]

## 👥 Contributi

[Istruzioni per contribuire al progetto]

## 📞 Supporto

[Informazioni di contatto o issue tracking]

---

**Versione:** 2.1.0.0
