# Phishing URL Detector

Aplikacja w Pythonie do wykrywania phishingowych adresów URL. Analizuje URL pod
kątem zestawu cech (długość, podejrzane domeny, homoglyphy/IDN, brak SSL, słowa
wrażliwe itd.), wylicza **score 0–100**, sprawdza adres w lokalnej i zewnętrznej
**bliście zagrożeń** (PhishTank / Google Safe Browsing) i udostępnia wynik przez
**REST API** zbudowane na FastAPI.

Projekt na przedmiot **Architektura aplikacji** — nacisk położono na czytelną
**architekturę warstwową** i rozdzielenie odpowiedzialności.

---

## Architektura warstwowa

```
                 ┌─────────────────────────────────────────────┐
   HTTP / JSON   │  app/api      Warstwa prezentacji (REST)     │
  ───────────►   │  routes.py · schemas.py · dependencies.py    │
                 └───────────────────────┬─────────────────────┘
                                         │  wstrzykiwanie zależności
                 ┌───────────────────────▼─────────────────────┐
                 │  app/services   Warstwa aplikacji / logiki   │
                 │  detector.py (orkiestracja) · scoring.py     │
                 └───────────┬───────────────────────┬─────────┘
                             │                       │
          ┌──────────────────▼────────┐   ┌──────────▼───────────────────┐
          │ app/domain  Domena (czysta│   │ app/clients  Adaptery (porty)│
          │ logika, bez frameworka)   │   │ do źródeł zagrożeń            │
          │ features.py · models.py   │   │ local_blacklist · threat_*   │
          └───────────────────────────┘   └──────────────────────────────┘
```

Zależności są skierowane **do wewnątrz**: warstwy zewnętrzne (API) zależą od
wewnętrznych (domena), nigdy odwrotnie. Domena nie wie nic o HTTP ani FastAPI.

| Warstwa | Katalog | Odpowiedzialność |
|---|---|---|
| Prezentacja | `app/api` | Endpointy REST, walidacja wejścia/wyjścia (Pydantic), wstrzykiwanie zależności |
| Aplikacja | `app/services` | Orkiestracja analizy (`PhishingDetector`), logika scoringu |
| Domena | `app/domain` | Ekstrakcja cech URL, modele domenowe — czysty Python |
| Adaptery | `app/clients` | Klienci list zagrożeń (lokalna blacklista, PhishTank/Google) za wspólnym portem `ThreatClient` |
| Konfiguracja | `app/config.py` | Ustawienia ze zmiennych środowiskowych / `.env` |

Wymianę źródła zagrożeń lub dodanie nowej cechy wykonuje się bez dotykania
pozostałych warstw (zasada otwarte–zamknięte).

---

## Wykrywane cechy (12, wymagane min. 8)

`url_length`, `ip_as_host`, `at_symbol`, `many_subdomains`, `hyphen_in_domain`,
`suspicious_tld`, `homoglyph_idn`, `sensitive_keywords`, `no_https`,
`url_shortener`, `digit_ratio`, `many_query_params`.

Każda cecha ma wagę; suma wag uruchomionych cech (plus ewentualne trafienie na
bliście) daje końcowy score. Werdykt: `safe` < próg/2 ≤ `suspicious` < próg ≤ `phishing`.

---

## Wymagania i instalacja

Python 3.10+.

```bash
cd phishing-url-detector
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # opcjonalnie — działa też bez tego
```

Aplikacja działa **bez kluczy API** (domyślny tryb `mock`, offline). Aby włączyć
integrację na żywo z Google Safe Browsing, ustaw w `.env`:
`THREAT_CLIENT_MODE=live` oraz `GOOGLE_SAFE_BROWSING_API_KEY=...`.

---

## Integracja na zywo (Google Safe Browsing / PhishTank)

Domyslnie aplikacja dziala offline (tryb `mock`). Aby wlaczyc realne sprawdzanie
w zewnetrznych listach zagrozen, ustaw w `.env`:

```
THREAT_CLIENT_MODE=live
```

W trybie live klient pyta po kolei dostepne zrodla i zwraca pierwsze trafienie:

**PhishTank** dziala **nawet bez klucza** (z nizszym limitem zapytan), wiec samo
ustawienie `THREAT_CLIENT_MODE=live` juz wlacza realne sprawdzanie. Aby podniesc
limit, zaloz darmowe konto na https://phishtank.org, pobierz klucz aplikacji i
wpisz go jako `PHISHTANK_APP_KEY`.

**Google Safe Browsing** wymaga klucza API:
1. wejdz na https://console.cloud.google.com i zaloz (lub wybierz) projekt,
2. w bibliotece API wlacz usluge *Safe Browsing API*,
3. w sekcji *Credentials* utworz *API key*,
4. wpisz go do `.env` jako `GOOGLE_SAFE_BROWSING_API_KEY`.

> Uwaga: Safe Browsing v4 jest oznaczone jako *deprecated* (nastepca: v5 / Web Risk
> API), ale endpoint nadal dziala i wystarcza do projektu. Wymiana na inne zrodlo
> sprowadza sie do jednej klasy-adaptera (`app/clients/`) - reszta aplikacji bez zmian.

Jesli zewnetrzne API jest niedostepne (brak sieci, blad klucza), klient **nie
wywraca aplikacji** - zwraca wynik "brak trafienia" z informacja o bledzie, a
analiza heurystyczna (cechy + scoring) dziala dalej.

## Uruchomienie

```bash
uvicorn app.main:app --reload
# lub:  python -m app.main
```

Dokumentacja interaktywna (Swagger UI): http://127.0.0.1:8000/docs

**Formularz HTML** (frontend do testowania URL): http://127.0.0.1:8000/

---

## Endpointy REST

| Metoda | Ścieżka | Opis |
|---|---|---|
| GET  | `/health` | Status + tryb klienta zagrożeń |
| POST | `/analyze` | Analiza pojedynczego URL |
| POST | `/analyze/batch` | Analiza wsadowa (max 100 URL) |

### Przykłady

```bash
curl http://127.0.0.1:8000/health

curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure-login.tk/account/verify?id=1"}'
```

Przykładowa odpowiedź (skrócona):

```json
{
  "url": "http://paypal-secure-login.tk/account/verify?id=1",
  "score": 100,
  "verdict": "phishing",
  "triggered_count": 4,
  "features": [ { "name": "suspicious_tld", "triggered": true, "weight": 12, "detail": "tld=.tk" } ],
  "blacklist": { "listed": true, "source": "mock", "detail": "dopasowano znaną złośliwą domenę 'paypal-secure-login.tk'" }
}
```

```bash
curl -X POST http://127.0.0.1:8000/analyze/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://bit.ly/3xYz", "https://malware-test.com"]}'
```

---

## Testy

```bash
pip install pytest
pytest
```

---

## Struktura projektu

```
phishing-url-detector/
├── app/
│   ├── api/          # warstwa REST (routes, schemas, dependencies)
│   ├── services/     # detector (orkiestracja) + scoring
│   ├── domain/       # features (ekstrakcja cech) + models
│   ├── clients/      # local_blacklist, threat_client (PhishTank/Google), port base
│   ├── static/index.html  # formularz HTML (frontend)
│   ├── config.py
│   └── main.py
├── data/blacklist.txt
├── tests/
├── requirements.txt
└── .env.example
```
