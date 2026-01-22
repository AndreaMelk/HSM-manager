# Security Policy

## 🔒 Gestione Informazioni Sensibili

### Dati che NON devono MAI essere committati su Git:

1. **Configurazione HSM**
   - Indirizzi IP degli HSM
   - Porte di comunicazione
   - Credenziali di accesso
   - Token di autenticazione

2. **Materiale Crittografico**
   - Chiavi crittografiche (KEK, DEK, etc.)
   - Key Blocks TR-31
   - Check values
   - Key Components

3. **Dati di Output**
   - File CSV generati con chiavi
   - Log con informazioni sensibili
   - Backup di configurazioni

## ✅ File Safe da Committare

- Codice sorgente (HSM-manager.py)
- File di esempio (hsm_config.example.json)
- Documentazione (README.md, SECURITY.md)
- Template CSV vuoti
- .gitignore

## 🛡️ Best Practices

### Prima di ogni Commit

1. **Verifica .gitignore**
   ```bash
   git status
   ```
   Assicurati che `hsm_config.json` non appaia nella lista

2. **Scan per dati sensibili**
   ```bash
   grep -r "172\." .  # Cerca IP privati
   grep -r "192\.168\." .
   grep -r "10\." .
   ```

3. **Controlla le stringhe hardcoded**
   - Nessun IP dovrebbe essere nel codice
   - Nessuna password nel codice
   - Nessuna chiave nel codice

### Durante lo Sviluppo

1. **Usa sempre file di configurazione esterni**
   - Mai hardcodare configurazioni sensibili
   - Usa variabili d'ambiente quando possibile
   - Fornisci sempre file .example

2. **Logging**
   - NON loggare materiale crittografico
   - NON loggare chiavi o componenti
   - Oscura dati sensibili nei log

3. **File temporanei**
   - Pulisci file temporanei prima del commit
   - Aggiungi pattern al .gitignore

### Gestione Configurazione

```json
// ✅ CORRETTO - hsm_config.example.json (da committare)
{
  "hsm_ip": "YOUR_HSM_IP_HERE",
  "hsm_port": 1500,
  "debug_mode": false
}

// ❌ SBAGLIATO - Non committare configurazioni reali!
{
  "hsm_ip": "172.29.71.101",
  "hsm_port": 1500,
  "debug_mode": true
}
```

## 🚨 Cosa Fare in Caso di Leak

Se hai accidentalmente committato dati sensibili:

### 1. NON fare solo un nuovo commit
Un semplice commit di rimozione non elimina i dati dalla history di Git!

### 2. Rimuovi dalla history
```bash
# Per file specifici
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch hsm_config.json" \
  --prune-empty --tag-name-filter cat -- --all

# Forza il push
git push origin --force --all
```

### 3. Ruota le credenziali
- Cambia IP dell'HSM se esposto
- Notifica il team di sicurezza
- Aggiorna i firewall se necessario
- Ruota eventuali chiavi compromesse

### 4. Notifica
- Informa il responsabile della sicurezza
- Documenta l'incidente
- Implementa misure preventive

## 🔍 Tools di Verifica

### Git-secrets
```bash
# Installa git-secrets
brew install git-secrets  # macOS
apt-get install git-secrets  # Linux

# Configura per il repository
git secrets --install
git secrets --register-aws  # Per chiavi AWS
git secrets --add '172\.[0-9]+\.[0-9]+\.[0-9]+'  # IP privati
```

### Gitleaks
```bash
# Installa gitleaks
brew install gitleaks  # macOS

# Scansiona il repository
gitleaks detect --source . --verbose
```

### Pre-commit Hook

Crea `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Blocca commit di hsm_config.json
if git diff --cached --name-only | grep -q "hsm_config.json"; then
    echo "❌ ERRORE: Tentativo di commit di hsm_config.json!"
    echo "Questo file contiene informazioni sensibili."
    exit 1
fi

# Cerca IP privati nel codice
if git diff --cached | grep -qE "172\.[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "❌ ERRORE: Rilevato IP privato nel codice!"
    exit 1
fi

exit 0
```

Rendi eseguibile:
```bash
chmod +x .git/hooks/pre-commit
```

## 📋 Checklist Prima del Push

- [ ] `hsm_config.json` è nel .gitignore
- [ ] Nessun IP hardcoded nel codice
- [ ] Nessuna password o credenziale nel codice
- [ ] File .example sono aggiornati
- [ ] README è completo e aggiornato
- [ ] Test di sicurezza eseguiti
- [ ] Log review completata

## 📞 Contatti Sicurezza

In caso di dubbi o problemi di sicurezza:
- [Inserire contatto team security]
- [Inserire email security@]

## 📚 Riferimenti

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [Git Security Best Practices](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage)
