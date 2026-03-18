/**
 * SecureBank — Serveur de démonstration IDS
 * 
 * ⚠️  CE SERVEUR EST INTENTIONNELLEMENT VULNÉRABLE
 *     À DES FINS PÉDAGOGIQUES UNIQUEMENT.
 *     NE PAS DÉPLOYER EN PRODUCTION.
 */

const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

// ─── CONFIG ────────────────────────────────────────────────
const PORT = process.env.PORT || 3002;
const DB_PATH = path.join(__dirname, 'data', 'bank.db');

// ─── INIT EXPRESS ──────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // Sert les fichiers HTML statiques

// ─── INIT BASE DE DONNÉES ──────────────────────────────────
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
}

const db = new Database(DB_PATH);

// Création des tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    email   TEXT    NOT NULL UNIQUE,
    password TEXT   NOT NULL,
    name    TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    label       TEXT    NOT NULL,
    amount      REAL    NOT NULL,
    type        TEXT    NOT NULL CHECK(type IN ('in', 'out')),
    category    TEXT    NOT NULL,
    date        TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT    NOT NULL,
    route     TEXT    NOT NULL,
    payload   TEXT,
    threat    TEXT,
    timestamp TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// ─── SEED — Données initiales ──────────────────────────────
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
    db.prepare(`
    INSERT INTO users (email, password, name) VALUES
    ('admin@securebank.fr', 'Admin1234!', 'Administrateur'),
    ('alice@example.com',   'Alice5678!', 'Alice Martin'),
    ('bob@example.com',     'Bob9012!',   'Bob Dupont')
  `).run();

    const insertTx = db.prepare(`
    INSERT INTO transactions (user_id, label, amount, type, category, date)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

    const txData = [
        [1, 'Virement reçu — Entreprise Martin', 3200.00, 'in', 'Virement', '2025-03-15'],
        [1, 'Loyer Appartement Paris 11e', 950.00, 'out', 'Paiement', '2025-03-01'],
        [1, 'Amazon — Commande #112-334', 89.99, 'out', 'Paiement', '2025-02-28'],
        [1, 'Remboursement Assurance Santé', 126.40, 'in', 'Virement', '2025-02-22'],
        [1, 'Carrefour — Courses semaine', 67.30, 'out', 'Paiement', '2025-02-20'],
        [2, 'Salaire Mars', 2500.00, 'in', 'Virement', '2025-03-10'],
        [2, 'Netflix Abonnement', 15.99, 'out', 'Paiement', '2025-03-05'],
        [3, 'Freelance Projet Web', 1800.00, 'in', 'Virement', '2025-03-12'],
        [3, 'EDF Électricité', 120.00, 'out', 'Paiement', '2025-03-08'],
    ];

    for (const tx of txData) insertTx.run(...tx);

    console.log('✅ Base de données initialisée avec les données de démonstration.');
}

// ─── MIDDLEWARE — Logger toutes les requêtes ───────────────
app.use((req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} — IP: ${ip}`);
    next();
});

// ─── ROUTES ────────────────────────────────────────────────

/**
 * GET /
 * Sert la page d'accueil
 */
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

/**
 * POST /api/login
 * ⚠️ VOLONTAIREMENT VULNÉRABLE au Brute Force (pas de rate limiting)
 * 
 * Exemple d'attaque :
 *   curl -X POST http://localhost:3000/api/login \
 *     -H "Content-Type: application/json" \
 *     -d '{"email":"admin@securebank.fr","password":"mauvais"}'
 */
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Log de la tentative
    db.prepare(`
    INSERT INTO logs (ip, route, payload, threat)
    VALUES (?, ?, ?, ?)
  `).run(ip, '/api/login', JSON.stringify({ email }), 'bruteforce_attempt');

    // Requête SÉCURISÉE (paramétrisée) pour le login
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password);

    if (user) {
        res.json({ success: true, message: `Bienvenue, ${user.name} !`, userId: user.id });
    } else {
        res.status(401).json({ success: false, message: 'Identifiants incorrects.' });
    }
});

/**
 * GET /api/search?q=...
 * ⚠️ VOLONTAIREMENT VULNÉRABLE à la SQLi (concaténation directe)
 * 
 * Exemples d'attaques SQLi :
 *   Normal    : /api/search?q=virement
 *   SQLi 1    : /api/search?q=' OR '1'='1
 *   SQLi 2    : /api/search?q=' UNION SELECT id,email,password,email,email,email,email FROM users--
 *   SQLi 3    : /api/search?q='; DROP TABLE transactions;--
 */
app.get('/api/search', (req, res) => {
    const query = req.query.q || '';
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    // Détection basique pour le log (pas de blocage — c'est le but !)
    const sqliPatterns = [/'|--|;|\/\*|\*\//i, /union|select|insert|drop|update|delete/i];
    const isSuspicious = sqliPatterns.some(p => p.test(query));

    // Log de la requête
    db.prepare(`
    INSERT INTO logs (ip, route, payload, threat)
    VALUES (?, ?, ?, ?)
  `).run(ip, '/api/search', query, isSuspicious ? 'sqli_attempt' : null);

    try {
        // ⚠️ REQUÊTE VULNÉRABLE — Concaténation directe sans paramétrage
        const sql = `SELECT * FROM transactions WHERE label LIKE '%${query}%' OR category LIKE '%${query}%'`;
        console.log(`[SQL] ${sql}`);

        const results = db.prepare(sql).all();
        res.json({ success: true, query, count: results.length, results, sql_executed: sql });

    } catch (err) {
        // Renvoie l'erreur SQL (utile pour voir l'effet de la SQLi)
        res.status(500).json({ success: false, error: err.message, query });
    }
});

/**
 * POST /api/register
 * Créer un nouveau compte utilisateur
 */
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: 'Tous les champs sont requis.' });
    }

    db.prepare(`INSERT INTO logs (ip, route, payload, threat) VALUES (?, ?, ?, ?)`)
        .run(ip, '/api/register', JSON.stringify({ email }), null);

    try {
        const result = db.prepare(`INSERT INTO users (email, password, name) VALUES (?, ?, ?)`)
            .run(email, password, name);
        res.json({ success: true, message: 'Compte créé avec succès !', userId: result.lastInsertRowid });
    } catch (err) {
        if (err.message.includes('UNIQUE')) {
            res.status(409).json({ success: false, message: 'Cet email est déjà utilisé.' });
        } else {
            res.status(500).json({ success: false, message: err.message });
        }
    }
});

/**
 * GET /api/account/:id
 * Données de l'espace compte (utilisateur + transactions)
 */
app.get('/api/account/:id', (req, res) => {
    const userId = req.params.id;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    db.prepare(`INSERT INTO logs (ip, route, payload, threat) VALUES (?, ?, ?, ?)`)
        .run(ip, `/api/account/${userId}`, null, null);

    const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });

    const transactions = db.prepare(
        'SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC'
    ).all(userId);

    const totalIn = transactions.filter(t => t.type === 'in').reduce((s, t) => s + t.amount, 0);
    const totalOut = transactions.filter(t => t.type === 'out').reduce((s, t) => s + t.amount, 0);
    const balance = totalIn - totalOut;

    res.json({ success: true, user, balance, totalIn, totalOut, transactions });
});

/**
 * GET /api/logs
 * Retourne les logs d'attaques (pour l'IDS)
 */
app.get('/api/logs', (req, res) => {
    const logs = db.prepare('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').all();
    res.json({ count: logs.length, logs });
});

/**
 * GET /api/stats
 * Statistiques pour le dashboard IDS
 */
app.get('/api/stats', (req, res) => {
    const totalLogs = db.prepare('SELECT COUNT(*) as c FROM logs').get().c;
    const sqliCount = db.prepare("SELECT COUNT(*) as c FROM logs WHERE threat = 'sqli_attempt'").get().c;
    const bfCount = db.prepare("SELECT COUNT(*) as c FROM logs WHERE threat = 'bruteforce_attempt'").get().c;
    const topIPs = db.prepare('SELECT ip, COUNT(*) as count FROM logs GROUP BY ip ORDER BY count DESC LIMIT 5').all();

    res.json({ totalLogs, sqliCount, bruteforceCount: bfCount, topIPs });
});


/**
 * DELETE /api/reset-logs
 * Vide la table logs pour repartir proprement
 */
app.delete('/api/reset-logs', (req, res) => {
    try {
        db.prepare('DELETE FROM logs').run();
        const count = db.prepare('SELECT COUNT(*) as c FROM logs').get().c;
        res.json({ success: true, message: 'Logs vidés', remaining: count });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ─── DÉMARRAGE ─────────────────────────────────────────────
app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║       SecureBank — Serveur IDS Démo          ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log(`║  🌐  Site     : http://localhost:${PORT}          ║`);
    console.log(`║  🔐  Login    : http://localhost:${PORT}/login.html║`);
    console.log(`║  🔍  Search   : http://localhost:${PORT}/search.html║`);
    console.log(`║  📊  Logs API : http://localhost:${PORT}/api/logs  ║`);
    console.log(`║  📁  DB       : ${DB_PATH}  ║`);
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');
    console.log('⚠️  SERVEUR VULNÉRABLE — USAGE PÉDAGOGIQUE UNIQUEMENT');
    console.log('');
});