# Security Policy

## 🔒 Sensitive Information Management

### Data that MUST NEVER be committed to Git:

1. **HSM Configuration**
   - HSM IP addresses
   - Communication ports
   - Access credentials
   - Authentication tokens

2. **Cryptographic Material**
   - Cryptographic keys (KEK, DEK, etc.)
   - TR-31 Key Blocks
   - Check values
   - Key Components

3. **Output Data**
   - CSV files generated with keys
   - Logs with sensitive information
   - Configuration backups

## ✅ Safe Files to Commit

- Source code (HSM-manager.py)
- Example files (hsm_config.example.json)
- Documentation (README.md, SECURITY.md)
- Empty CSV templates
- .gitignore

## 🛡️ Best Practices

### Before Every Commit

1. **Verify .gitignore**
   ```bash
   git status
   ```
   Ensure `hsm_config.json` doesn't appear in the list

2. **Scan for sensitive data**
   ```bash
   grep -r "172\." .  # Search for private IPs
   grep -r "192\.168\." .
   grep -r "10\." .
   ```

3. **Check hardcoded strings**
   - No IPs should be in the code
   - No passwords in the code
   - No keys in the code

### During Development

1. **Always use external configuration files**
   - Never hardcode sensitive configurations
   - Use environment variables when possible
   - Always provide .example files

2. **Logging**
   - DO NOT log cryptographic material
   - DO NOT log keys or components
   - Obscure sensitive data in logs

3. **Temporary files**
   - Clean temporary files before commit
   - Add patterns to .gitignore

### Configuration Management

```json
// ✅ CORRECT - hsm_config.example.json (to commit)
{
  "hsm_ip": "YOUR_HSM_IP_HERE",
  "hsm_port": 1500,
  "debug_mode": false
}

// ❌ WRONG - Don't commit real configurations!
{
  "hsm_ip": "172.29.71.101",
  "hsm_port": 1500,
  "debug_mode": true
}
```

## 🚨 What to Do in Case of Leak

If you accidentally committed sensitive data:

### 1. DO NOT just make a new commit
A simple removal commit doesn't delete data from Git history!

### 2. Remove from history
```bash
# For specific files
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch hsm_config.json" \
  --prune-empty --tag-name-filter cat -- --all

# Force push
git push origin --force --all
```

### 3. Rotate credentials
- Change HSM IP if exposed
- Notify security team
- Update firewalls if necessary
- Rotate any compromised keys

### 4. Notification
- Inform security manager
- Document the incident
- Implement preventive measures

## 🔍 Verification Tools

### Git-secrets
```bash
# Install git-secrets
brew install git-secrets  # macOS
apt-get install git-secrets  # Linux

# Configure for repository
git secrets --install
git secrets --register-aws  # For AWS keys
git secrets --add '172\.[0-9]+\.[0-9]+\.[0-9]+'  # Private IPs
```

### Gitleaks
```bash
# Install gitleaks
brew install gitleaks  # macOS

# Scan repository
gitleaks detect --source . --verbose
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

# Block commit of hsm_config.json
if git diff --cached --name-only | grep -q "hsm_config.json"; then
    echo "❌ ERROR: Attempt to commit hsm_config.json!"
    echo "This file contains sensitive information."
    exit 1
fi

# Search for private IPs in code
if git diff --cached | grep -qE "172\.[0-9]+\.[0-9]+\.[0-9]+"; then
    echo "❌ ERROR: Private IP detected in code!"
    exit 1
fi

exit 0
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

## 📋 Pre-Push Checklist

- [ ] `hsm_config.json` is in .gitignore
- [ ] No hardcoded IPs in code
- [ ] No passwords or credentials in code
- [ ] .example files are updated
- [ ] README is complete and updated
- [ ] Security tests executed
- [ ] Log review completed

## 📞 Security Contacts

In case of doubts or security issues:
- [Insert security team contact]
- [Insert security@ email]

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [Git Security Best Practices](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage)
