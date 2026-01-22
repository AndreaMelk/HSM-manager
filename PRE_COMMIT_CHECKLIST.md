# 📋 Pre-Commit Checklist for Git

Use this checklist before every Git push to ensure the code is secure.

## ✅ Mandatory Checks

### 1. Configuration Files
- [ ] `hsm_config.json` is NOT in staging area
  ```bash
  git status
  # hsm_config.json MUST NOT appear in "Changes to be committed"
  ```
- [ ] `hsm_config.example.json` is present and updated
- [ ] `.gitignore` contains `hsm_config.json`

### 2. Source Code
- [ ] No hardcoded IPs in code
  ```bash
  grep -r "172\." *.py
  grep -r "192\.168\." *.py
  grep -r "10\." *.py
  # If found, verify it's only in comments or examples
  ```
- [ ] No passwords or credentials
  ```bash
  grep -ri "password.*=.*['\"]" *.py
  grep -ri "token.*=.*['\"]" *.py
  ```
- [ ] No cryptographic keys
  ```bash
  # Keys have typical patterns
  grep -E "[A-F0-9]{32,}" *.py
  ```

### 3. Documentation
- [ ] README.md is updated with correct instructions
- [ ] SECURITY.md reflects current policies
- [ ] Code comments don't contain sensitive info

### 4. Output Files
- [ ] Directory `hsm_output/` is not tracked
- [ ] Generated `.csv` files are not in staging area
- [ ] `.log` files are not tracked

## 🔍 Quick Verification Commands

### Complete Scan
```bash
# Check all staged files
git diff --cached

# List files to commit
git status

# Search for sensitive patterns
git diff --cached | grep -E "(172\.|192\.168\.|10\.)[0-9]+"
git diff --cached | grep -Ei "(password|token|secret|api[_-]?key)\s*[:=]"
```

### Test Pre-Commit Hook
```bash
# Install pre-commit hook
cp pre-commit.example .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# Hook will run automatically on every commit
git commit -m "test"
```

## 🚨 If You Find Issues

### Hardcoded IP
1. Move IP to `hsm_config.json`
2. Update code to read from configuration
3. Verify it works with IP from file

### Sensitive Files in Stage
```bash
# Remove file from stage
git reset HEAD hsm_config.json

# If already committed (NOT pushed)
git reset --soft HEAD~1
git reset HEAD hsm_config.json
git commit
```

### Exposed Credentials
1. Remove credentials from code
2. Use environment variables or config file
3. Update documentation

## 📦 Before Final Push

```bash
# 1. Verify branch
git branch
# Make sure you're on the correct branch

# 2. Verify history
git log --oneline -5
# Check for suspicious commits

# 3. Final review
git diff origin/main..HEAD
# Review ALL changes you're about to push

# 4. Final test
python3 HSM-manager.py
# Ensure it works with hsm_config.json

# 5. Push
git push origin main
```

## ✨ Continuous Best Practices

### Every Week
- [ ] Review week's commits
- [ ] Verify .gitignore is effective
- [ ] Check no sensitive files ended up in Git

### Every Month
- [ ] Complete repository audit
- [ ] Update documentation
- [ ] Review security policies

### After Major Changes
- [ ] Complete application test
- [ ] Verify hsm_config.example.json is updated
- [ ] Update README with new features

## 📞 When in Doubt

If you're unsure:
1. **DO NOT push**
2. Ask team for review
3. Verify with security team
4. Better to be cautious than risk exposure

## 🎯 Quick Security Check Command

Copy-paste this before every commit:

```bash
echo "🔍 Security Check..." && \
git status | grep -q "hsm_config.json" && echo "❌ hsm_config.json in stage!" || \
(git diff --cached | grep -qE "(172\.|192\.168\.|10\.)[0-9]+" && echo "❌ IP found!" || \
echo "✅ Looks OK!")
```

---

**Remember**: Security is everyone's responsibility. A minute of checking now can prevent hours of problems later!
