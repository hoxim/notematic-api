# Notematic API

Backend API dla aplikacji Notematic - system zarządzania notatkami z autentykacją JWT i bazą danych CouchDB.

## 🚀 Szybki Start

### Lokalne uruchomienie

```bash
# Klonuj repozytorium
git clone <your-repo-url>
cd notematic-api

# Zainstaluj Rust (jeśli nie masz)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Uruchom API
cargo run
```

### Automatyczne wdrażanie

API jest skonfigurowane do automatycznego wdrażania na serwer po push na GitHub.

📖 **Zobacz:** [QUICK_START.md](QUICK_START.md) - instrukcje szybkiego startu

## 📋 Funkcjonalności

- ✅ **Autentykacja JWT** - rejestracja, logowanie, refresh tokenów
- ✅ **Rate limiting** - ochrona przed spamem
- ✅ **CouchDB** - baza danych NoSQL
- ✅ **CRUD operacje** - zarządzanie notatkami i notatnikami
- ✅ **Logowanie** - szczegółowe logi z różnymi poziomami
- ✅ **CORS** - obsługa cross-origin requests
- ✅ **Automatyczne wdrażanie** - CI/CD z GitHub Actions

## 🏗️ Architektura

```
notematic-api/
├── src/
│   ├── main.rs          # Główny plik aplikacji
│   ├── handlers.rs      # Obsługa requestów HTTP
│   ├── models.rs        # Modele danych
│   ├── routes.rs        # Definicje routingu
│   ├── middleware.rs    # Middleware (JWT, rate limiting)
│   └── utils.rs         # Narzędzia (JWT, hashowanie)
├── .github/workflows/   # GitHub Actions
├── scripts/             # Skrypty deploymentu
└── config.production.toml # Konfiguracja produkcyjna
```

## 🔧 Konfiguracja

### Zmienne środowiskowe

```bash
RUST_ENV=development
API_PORT=8080
RUST_LOG=info
COUCHDB_URL=http://localhost:5984
COUCHDB_USERNAME=admin
COUCHDB_PASSWORD=your_password
JWT_SECRET=your_jwt_secret
```

### Konfiguracja produkcyjna

Edytuj `config.production.toml`:

```toml
[server]
port = 8080
host = "0.0.0.0"

[database]
couchdb_url = "http://localhost:5984"
couchdb_username = "admin"
couchdb_password = "your_secure_password"

[jwt]
secret = "your_super_secure_jwt_secret"
access_expiry = 3600
refresh_expiry = 2592000
```

## 📡 API Endpoints

### Publiczne

- `POST /register` - Rejestracja użytkownika
- `POST /login` - Logowanie użytkownika
- `POST /refresh` - Odświeżenie tokenu

### Chronione (wymagają JWT)

- `GET /protected/notebooks` - Lista notatników użytkownika
- `POST /protected/notebooks` - Utworzenie notatnika
- `GET /protected/notebooks/{id}/notes` - Lista notatek w notatniku
- `POST /protected/notebooks/{id}/notes` - Utworzenie notatki
- `PUT /protected/notebooks/{id}` - Aktualizacja notatnika
- `DELETE /protected/notebooks/{id}` - Usunięcie notatnika

## 🚀 Deployment

### Automatyczne wdrażanie

API jest skonfigurowane do automatycznego wdrażania na serwer po push na gałąź `main`.

**Wymagania serwera:**
- Linux (Ubuntu 20.04+)
- SSH dostęp z sudo
- CouchDB
- Port 8080 dostępny

**Konfiguracja GitHub Secrets:**
- `SERVER_HOST` - IP/domena serwera
- `SERVER_USERNAME` - użytkownik SSH
- `SERVER_SSH_KEY` - klucz prywatny SSH
- `SERVER_PORT` - port SSH (zazwyczaj 22)

📖 **Szczegółowe instrukcje:**
- [QUICK_START.md](QUICK_START.md) - szybki start
- [GITHUB_SETUP.md](GITHUB_SETUP.md) - konfiguracja GitHub
- [DEPLOYMENT.md](DEPLOYMENT.md) - pełna dokumentacja

### Ręczne wdrażanie

```bash
# Budowanie
cargo build --release

# Utworzenie pakietu
mkdir -p release
cp target/release/notematic-api release/
cp Cargo.toml release/
cp -r src release/
tar -czf notematic-api.tar.gz release/

# Wdrożenie na serwer
scp notematic-api.tar.gz username@server:/opt/notematic-api/
ssh username@server
cd /opt/notematic-api
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

## 📊 Monitoring

### Status serwisu

```bash
# Sprawdź status
sudo systemctl status notematic-api

# Logi na żywo
sudo journalctl -u notematic-api -f

# Ostatnie logi
sudo journalctl -u notematic-api --no-pager -l -n 50
```

### Backup i rollback

```bash
# Lista backupów
ls -la /opt/notematic-api/backup/

# Przywrócenie backupu
sudo systemctl stop notematic-api
sudo cp /opt/notematic-api/backup/notematic-api.YYYYMMDD_HHMMSS /opt/notematic-api/notematic-api
sudo systemctl start notematic-api
```

## 🧪 Testowanie

### Lokalne testy

```bash
# Uruchom testy
cargo test

# Test z logami
RUST_LOG=debug cargo test
```

### Test API

```bash
# Rejestracja
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'

# Logowanie
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# Utworzenie notatnika (z tokenem)
curl -X POST http://localhost:8080/protected/notebooks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Notebook","description":"Test notebook"}'
```

## 🔒 Bezpieczeństwo

- **JWT tokens** - bezpieczna autentykacja
- **Rate limiting** - ochrona przed spamem
- **CORS** - kontrolowany dostęp cross-origin
- **Hashowanie haseł** - bcrypt
- **Systemd service** - izolowany użytkownik
- **Automatyczne backupy** - przed każdym deploymentem

## 🛠️ Rozwój

### Struktura projektu

```
src/
├── main.rs          # Główny plik aplikacji
├── handlers.rs      # Obsługa requestów HTTP
├── models.rs        # Modele danych (User, Notebook, Note)
├── routes.rs        # Definicje routingu
├── middleware.rs    # Middleware (JWT, rate limiting)
└── utils.rs         # Narzędzia (JWT, hashowanie, CouchDB)
```

### Dodawanie nowych endpointów

1. Dodaj handler w `handlers.rs`
2. Dodaj route w `routes.rs`
3. Dodaj model w `models.rs` (jeśli potrzebne)
4. Przetestuj endpoint

### Logowanie

```rust
use log::{info, warn, error, debug};

info!("User registered: {}", username);
warn!("Rate limit exceeded for IP: {}", ip);
error!("Database connection failed: {}", err);
debug!("Processing request: {:?}", request);
```

## 📝 Licencja

MIT License - zobacz [LICENSE](LICENSE) dla szczegółów.

## 🤝 Współpraca

1. Fork repozytorium
2. Utwórz feature branch (`git checkout -b feature/amazing-feature`)
3. Commit zmiany (`git commit -m 'Add amazing feature'`)
4. Push do branch (`git push origin feature/amazing-feature`)
5. Otwórz Pull Request

## 📞 Wsparcie

- **Dokumentacja:** [DEPLOYMENT.md](DEPLOYMENT.md)
- **GitHub Issues:** Zgłoś błąd lub sugestię
- **Discussions:** Dyskusje i pytania

---

**Notematic API** - Bezpieczne i skalowalne API dla aplikacji notatek 🚀 