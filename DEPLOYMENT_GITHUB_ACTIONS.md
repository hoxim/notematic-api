# GitHub Actions Deployment Guide

## Ręczny Deploy przez GitHub

Teraz możesz ręcznie uruchomić deploy przez przycisk na GitHub!

### Jak uruchomić ręczny deploy:

1. **Przejdź do zakładki "Actions"** w repozytorium GitHub
2. **Wybierz workflow "Build and Deploy API"**
3. **Kliknij "Run workflow"** (niebieski przycisk)
4. **Wybierz opcje:**
   - **Environment**: `production` lub `staging`
   - **Force deploy**: `true` (jeśli chcesz pominąć testy) lub `false`
5. **Kliknij "Run workflow"**

### Opcje deployu:

#### Environment
- **production** - Deploy do środowiska produkcyjnego
- **staging** - Deploy do środowiska testowego

#### Force deploy
- **false** (domyślnie) - Deploy tylko jeśli wszystkie testy przejdą
- **true** - Deploy nawet jeśli testy nie przejdą (użyj ostrożnie!)

### Automatyczny deploy

Deploy uruchamia się automatycznie gdy:
- Push do branch `main` lub `master`
- Pull request do `main` lub `master`
- Zmiany w folderze `notematic-api/**`

### Weryfikacja deployu

Po deployu automatycznie sprawdzane jest:
- ✅ Status serwisu systemd
- ✅ Health check endpoint (`/health`)
- ✅ Logi serwisu

### Health Check Endpoint

API ma teraz endpoint `/health` który zwraca:
```json
{
  "status": "healthy",
  "environment": "production",
  "version": "1.0.0",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Troubleshooting

Jeśli deploy się nie powiedzie:

1. **Sprawdź logi** w zakładce Actions
2. **Sprawdź status serwisu** na serwerze:
   ```bash
   sudo systemctl status notematic-api
   ```
3. **Sprawdź logi serwisu**:
   ```bash
   sudo journalctl -u notematic-api -f
   ```
4. **Sprawdź połączenie z bazą danych**:
   ```bash
   curl -u hoxim:password http://192.168.50.90:5984/
   ```

### Konfiguracja Secrets

Upewnij się, że masz skonfigurowane następujące secrets w GitHub:
- `SERVER_HOST` - Adres serwera
- `SERVER_USERNAME` - Nazwa użytkownika SSH
- `SERVER_SSH_KEY` - Klucz SSH (private key)
- `SERVER_PORT` - Port SSH (domyślnie 22)

### Backup

Przed każdym deployem automatycznie tworzony jest backup poprzedniej wersji w `/opt/notematic-api/backup/`. 