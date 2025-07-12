# GitHub Actions Setup Guide

## Konfiguracja GitHub Secrets

Aby automatyczne wdrażanie działało, musisz skonfigurować sekrety w swoim repozytorium GitHub.

### Krok 1: Przejdź do ustawień repozytorium

1. Otwórz swoje repozytorium na GitHub
2. Kliknij zakładkę **Settings**
3. W menu po lewej stronie kliknij **Secrets and variables** → **Actions**

### Krok 2: Dodaj sekrety

Kliknij **New repository secret** i dodaj następujące sekrety:

#### 1. SERVER_HOST
- **Name**: `SERVER_HOST`
- **Value**: IP adres lub domena Twojego serwera
- **Przykład**: `192.168.1.100` lub `api.twoja-domena.com`

#### 2. SERVER_USERNAME
- **Name**: `SERVER_USERNAME`
- **Value**: Nazwa użytkownika SSH na serwerze
- **Przykład**: `ubuntu`, `root`, `deploy`

#### 3. SERVER_SSH_KEY
- **Name**: `SERVER_SSH_KEY`
- **Value**: Zawartość prywatnego klucza SSH (cały klucz)
- **Przykład**:
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAv8vx8qQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQqQq
...
-----END OPENSSH PRIVATE KEY-----
```

#### 4. SERVER_PORT
- **Name**: `SERVER_PORT`
- **Value**: Port SSH (zazwyczaj 22)
- **Przykład**: `22`

### Krok 3: Generowanie klucza SSH (jeśli potrzebne)

Jeśli nie masz jeszcze klucza SSH:

```bash
# Wygeneruj nowy klucz SSH
ssh-keygen -t rsa -b 4096 -C "github-actions@twoja-domena.com"

# Skopiuj klucz publiczny na serwer
ssh-copy-id -i ~/.ssh/id_rsa.pub username@twoj-serwer

# Wyświetl zawartość klucza prywatnego (skopiuj całą zawartość)
cat ~/.ssh/id_rsa
```

### Krok 4: Testowanie połączenia

Przetestuj połączenie SSH z serwera:

```bash
# Test połączenia
ssh username@twoj-serwer "echo 'Połączenie działa!'"
```

## Struktura sekretów

Po skonfigurowaniu, Twoje sekrety powinny wyglądać tak:

| Name | Value |
|------|-------|
| `SERVER_HOST` | `192.168.1.100` |
| `SERVER_USERNAME` | `ubuntu` |
| `SERVER_SSH_KEY` | `-----BEGIN OPENSSH PRIVATE KEY-----...` |
| `SERVER_PORT` | `22` |

## Bezpieczeństwo

### Ważne uwagi bezpieczeństwa:

1. **Nigdy nie commituj kluczy SSH** do repozytorium
2. **Używaj dedykowanego klucza** dla GitHub Actions
3. **Ogranicz uprawnienia** użytkownika na serwerze
4. **Regularnie rotuj klucze** (co 3-6 miesięcy)
5. **Monitoruj logi** dostępu SSH

### Tworzenie dedykowanego użytkownika (zalecane)

```bash
# Na serwerze
sudo adduser github-actions
sudo usermod -aG sudo github-actions

# Skopiuj klucz tylko dla tego użytkownika
sudo mkdir -p /home/github-actions/.ssh
sudo cp ~/.ssh/authorized_keys /home/github-actions/.ssh/
sudo chown -R github-actions:github-actions /home/github-actions/.ssh
sudo chmod 700 /home/github-actions/.ssh
sudo chmod 600 /home/github-actions/.ssh/authorized_keys
```

## Troubleshooting

### Problem: "Permission denied (publickey)"

**Rozwiązanie:**
1. Sprawdź czy klucz publiczny jest na serwerze:
   ```bash
   cat ~/.ssh/authorized_keys
   ```

2. Sprawdź uprawnienia:
   ```bash
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/authorized_keys
   ```

3. Testuj połączenie z verbose:
   ```bash
   ssh -v username@serwer
   ```

### Problem: "Host key verification failed"

**Rozwiązanie:**
1. Dodaj serwer do known_hosts:
   ```bash
   ssh-keyscan -H twoj-serwer >> ~/.ssh/known_hosts
   ```

### Problem: "sudo: no tty present and no askpass program specified"

**Rozwiązanie:**
1. Dodaj użytkownika do sudoers bez hasła:
   ```bash
   sudo visudo
   # Dodaj linię:
   username ALL=(ALL) NOPASSWD: ALL
   ```

## Monitoring

### Sprawdzanie statusu workflow

1. Przejdź do zakładki **Actions** w repozytorium
2. Kliknij na konkretny workflow
3. Sprawdź logi każdego kroku

### Logi na serwerze

```bash
# Sprawdź status serwisu
sudo systemctl status notematic-api

# Zobacz logi
sudo journalctl -u notematic-api -f

# Sprawdź logi systemd
sudo journalctl -u notematic-api --no-pager -l
```

## Automatyczne powiadomienia

Możesz dodać powiadomienia o statusie deploymentu:

### Slack
Dodaj sekret `SLACK_WEBHOOK_URL` i zaktualizuj workflow.

### Email
Użyj akcji `dawidd6/action-send-mail`.

### Discord
Użyj akcji `Ilshidur/action-discord`.

## Backup i rollback

### Automatyczny rollback w przypadku błędu

Workflow automatycznie tworzy backup przed deploymentem. W przypadku błędu:

```bash
# Na serwerze
sudo systemctl stop notematic-api
sudo cp /opt/notematic-api/backup/notematic-api.YYYYMMDD_HHMMSS /opt/notematic-api/notematic-api
sudo systemctl start notematic-api
```

### Sprawdzanie backupów

```bash
# Lista dostępnych backupów
ls -la /opt/notematic-api/backup/

# Przywrócenie konkretnego backupu
sudo cp /opt/notematic-api/backup/notematic-api.20241201_143022 /opt/notematic-api/notematic-api
``` 