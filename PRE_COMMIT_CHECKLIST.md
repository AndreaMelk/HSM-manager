# 📋 Checklist Pre-Commit su Git

Usa questa checklist prima di ogni push su Git per assicurarti che il codice sia sicuro.

## ✅ Controlli Obbligatori

### 1. File di Configurazione
- [ ] `hsm_config.json` NON è nell'area di stage
  ```bash
  git status
  # hsm_config.json NON deve apparire in "Changes to be committed"
  ```
- [ ] `hsm_config.example.json` è presente e aggiornato
- [ ] `.gitignore` contiene `hsm_config.json`

### 2. Codice Sorgente
- [ ] Nessun IP hardcoded nel codice
  ```bash
  grep -r "172\." *.py
  grep -r "192\.168\." *.py
  grep -r "10\." *.py
  # Se trova qualcosa, verifica che sia solo nei commenti o esempi
  ```
- [ ] Nessuna password o credenziale
  ```bash
  grep -ri "password.*=.*['\"]" *.py
  grep -ri "token.*=.*['\"]" *.py
  ```
- [ ] Nessuna chiave crittografica
  ```bash
  # Le chiavi hanno pattern tipici
  grep -E "[A-F0-9]{32,}" *.py
  ```

### 3. Documentazione
- [ ] README.md è aggiornato con le istruzioni corrette
- [ ] SECURITY.md riflette le policy attuali
- [ ] Commenti nel codice non contengono info sensibili

### 4. File di Output
- [ ] Directory `hsm_output/` non è tracciata
- [ ] File `.csv` generati non sono nell'area di stage
- [ ] File `.log` non sono tracciati

## 🔍 Comandi di Verifica Rapida

### Scansione Completa
```bash
# Controlla tutti i file in stage
git diff --cached

# Lista file da committare
git status

# Cerca pattern sensibili
git diff --cached | grep -E "(172\.|192\.168\.|10\.)[0-9]+"
git diff --cached | grep -Ei "(password|token|secret|api[_-]?key)\s*[:=]"
```

### Test Pre-Commit Hook
```bash
# Installa il pre-commit hook
cp pre-commit.example .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Il hook verrà eseguito automaticamente ad ogni commit
git commit -m "test"
```

## 🚨 Se Trovi Problemi

### IP Hardcoded
1. Sposta l'IP in `hsm_config.json`
2. Aggiorna il codice per leggere da configurazione
3. Verifica che funzioni con IP da file

### File Sensibili in Stage
```bash
# Rimuovi file dallo stage
git reset HEAD hsm_config.json

# Se già committato (NON pushato)
git reset --soft HEAD~1
git reset HEAD hsm_config.json
git commit
```

### Credenziali Esposte
1. Rimuovi le credenziali dal codice
2. Usa variabili d'ambiente o file di config
3. Aggiorna la documentazione

## 📦 Prima del Push Finale

```bash
# 1. Verifica branch
git branch
# Assicurati di essere sul branch corretto

# 2. Verifica history
git log --oneline -5
# Controlla che non ci siano commit sospetti

# 3. Review finale
git diff origin/main..HEAD
# Review di TUTTI i cambiamenti che stai per pushare

# 4. Test finale
python3 HSM-manager.py
# Assicurati che funzioni con hsm_config.json

# 5. Push
git push origin main
```

## ✨ Best Practices Continuative

### Ogni Settimana
- [ ] Review dei commit della settimana
- [ ] Verifica che .gitignore sia efficace
- [ ] Controlla che nessun file sensibile sia finito su Git

### Ogni Mese
- [ ] Audit completo del repository
- [ ] Aggiorna la documentazione
- [ ] Review delle policy di sicurezza

### Dopo Modifiche Maggiori
- [ ] Test completo dell'applicazione
- [ ] Verifica che hsm_config.example.json sia aggiornato
- [ ] Update del README con nuove features

## 📞 In Caso di Dubbi

Se non sei sicuro:
1. **NON fare il push**
2. Chiedi review al team
3. Verifica con il security team
4. Meglio essere prudenti che rischiare

## 🎯 Comando Rapido di Verifica

Copia-incolla questo prima di ogni commit:

```bash
echo "🔍 Security Check..." && \
git status | grep -q "hsm_config.json" && echo "❌ hsm_config.json in stage!" || \
(git diff --cached | grep -qE "(172\.|192\.168\.|10\.)[0-9]+" && echo "❌ IP trovato!" || \
echo "✅ Sembra OK!")
```

---

**Ricorda**: La sicurezza è responsabilità di tutti. Un minuto di controllo ora può evitare ore di problemi dopo!
