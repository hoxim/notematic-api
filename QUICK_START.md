# 🚀 Szybki Start - Automatyczne Wdrażanie API

## Co zostało skonfigurowane

✅ **GitHub Actions workflow** - automatyczne budowanie i wdrażanie  
✅ **Skrypt deploymentu** - bezpieczne wdrażanie na serwer  
✅ **Systemd service** - automatyczne uruchamianie i restart  
✅ **Backup system** - automatyczne kopie zapasowe  
✅ **Testy połączenia** - weryfikacja przed deploymentem  

## Kroki do wykonania

### 1. Przygotuj serwer

```bash
# Zaloguj się na serwer
ssh username@twoj-serwer

# Zainstaluj CouchDB (jeśli nie masz)
sudo apt update
sudo apt install couchdb

# Utwórz katalog aplikacji
sudo mkdir -p /opt/notematic-api/backup
```

### 2. Skonfiguruj GitHub Secrets

1. Przejdź do swojego repozytorium na GitHub
2. **Settings** → **Secrets and variables** → **Actions**
3. Dodaj sekrety:

| Nazwa | Wartość |
|-------|---------|
| `SERVER_HOST` | IP lub domena serwera |
| `SERVER_USERNAME` | Nazwa użytkownika SSH |
| `SERVER_SSH_KEY` | Zawartość klucza prywatnego SSH |
| `SERVER_PORT` | Port SSH (zazwyczaj 22) |

### 3. Wygeneruj klucz SSH (jeśli potrzebne)

```bash
# Na swoim komputerze
ssh-keygen -t rsa -b 4096 -C "github-actions@twoja-domena.com"

# Skopiuj klucz na serwer
ssh-copy-id -i ~/.ssh/id_rsa.pub username@twoj-serwer

# Skopiuj zawartość klucza prywatnego do GitHub Secret
cat ~/.ssh/id_rsa
```

### 4. Skonfiguruj użytkownika na serwerze

```bash
# Na serwerze - dodaj użytkownika do sudoers bez hasła
sudo visudo
# Dodaj linię:
username ALL=(ALL) NOPASSWD: ALL
```

### 5. Wypchnij kod na GitHub

```bash
# Dodaj pliki do repozytorium
git add .
git commit -m "Add CI/CD pipeline for automatic deployment"
git push origin main
```

### 6. Sprawdź deployment

1. Przejdź do zakładki **Actions** w repozytorium
2. Zobaczysz uruchomiony workflow "Build and Deploy API"
3. Poczekaj na zakończenie (około 2-3 minuty)

### 7. Sprawdź czy API działa

```bash
# Na serwerze
sudo systemctl status notematic-api

# Sprawdź logi
sudo journalctl -u notematic-api -f

# Test API
curl http://twoj-serwer:8080/health
```

## 🔧 Konfiguracja środowiska

### Zmień konfigurację produkcyjną

Edytuj `config.production.toml`:

```toml
[server]
port = 8080
host = "0.0.0.0"

[database]
couchdb_url = "http://localhost:5984"
couchdb_username = "admin"
couchdb_password = "twoje_haslo"

[jwt]
secret = "twoj_super_bezpieczny_jwt_secret"
```

### Otwórz port w firewall

```bash
# Ubuntu/Debian
sudo ufw allow 8080

# Lub iptables
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

## 📊 Monitoring

### Sprawdź status serwisu

```bash
# Status
sudo systemctl status notematic-api

# Logi na żywo
sudo journalctl -u notematic-api -f

# Ostatnie logi
sudo journalctl -u notematic-api --no-pager -l -n 50
```

### Sprawdź backupy

```bash
# Lista backupów
ls -la /opt/notematic-api/backup/

# Przywróć backup (jeśli potrzebne)
sudo systemctl stop notematic-api
sudo cp /opt/notematic-api/backup/notematic-api.YYYYMMDD_HHMMSS /opt/notematic-api/notematic-api
sudo systemctl start notematic-api
```

## 🚨 Troubleshooting

### Problem: "Permission denied (publickey)"

```bash
# Sprawdź klucz na serwerze
cat ~/.ssh/authorized_keys

# Sprawdź uprawnienia
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

### Problem: "sudo: no tty present"

```bash
# Dodaj użytkownika do sudoers
sudo visudo
# Dodaj: username ALL=(ALL) NOPASSWD: ALL
```

### Problem: Port 8080 zajęty

```bash
# Sprawdź co używa portu
sudo netstat -tlnp | grep :8080

# Zatrzymaj proces lub zmień port w konfiguracji
```

### Problem: CouchDB nie działa

```bash
# Sprawdź status CouchDB
sudo systemctl status couchdb

# Uruchom CouchDB
sudo systemctl start couchdb
sudo systemctl enable couchdb
```

## 🔄 Automatyczne aktualizacje

Po skonfigurowaniu, każde push do gałęzi `main` automatycznie:

1. ✅ Buduje API na GitHub Actions
2. ✅ Uruchamia testy
3. ✅ Tworzy backup poprzedniej wersji
4. ✅ Wdraża nową wersję na serwer
5. ✅ Uruchamia serwis
6. ✅ Sprawdza czy wszystko działa

## 📝 Logi i monitoring

### GitHub Actions
- Przejdź do **Actions** w repozytorium
- Zobaczysz historię wszystkich deploymentów
- Kliknij na konkretny workflow, aby zobaczyć szczegóły

### Serwer
- Logi aplikacji: `sudo journalctl -u notematic-api -f`
- Logi systemowe: `sudo journalctl -f`
- Status serwisu: `sudo systemctl status notematic-api`

## 🎉 Gotowe!

Twoje API jest teraz skonfigurowane do automatycznego wdrażania. Każdy commit na `main` automatycznie zaktualizuje API na serwerze.

### Następne kroki:
1. Skonfiguruj domenę i SSL (nginx + Let's Encrypt)
2. Dodaj monitoring (Prometheus + Grafana)
3. Skonfiguruj alerty (email/Slack)
4. Dodaj testy automatyczne
5. Skonfiguruj staging environment

---

**Potrzebujesz pomocy?** Sprawdź pełną dokumentację w `DEPLOYMENT.md` i `GITHUB_SETUP.md` 