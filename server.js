const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3002;
const DB_PATH = path.join(__dirname, 'data', 'bank.db');

// ─── URL du Guardian Python ────────────────────────────────
const GUARDIAN_URL = process.env.GUARDIAN_URL || 'http://localhost:8000';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── INIT BASE DE DONNÉES ──────────────────────────────────
if (!fs.existsSync(path.join(__dirname, 'data'))) {
    fs.mkdirSync(path.join(__dirname, 'data'));
}

const db = new Database(DB_PATH);
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
`);

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
    const today = new Date().toISOString().split('T')[0];
    const txData = [
        [1, 'Virement reçu — Entreprise Martin', 3200.00, 'in',  'Virement', '2025-03-15'],
        [1, 'Loyer Appartement Paris 11e',        950.00,  'out', 'Paiement', '2025-03-01'],
        [1, 'Amazon — Commande #112-334',          89.99,  'out', 'Paiement', '2025-02-28'],
        [1, 'Remboursement Assurance Santé',       126.40, 'in',  'Virement', '2025-02-22'],
        [1, 'Carrefour — Courses semaine',          67.30,  'out', 'Paiement', '2025-02-20'],
        [1, 'Bonus annuel entreprise',            5000.00, 'in',  'Virement', '2025-01-10'],
        [2, 'Salaire Mars',                       2500.00, 'in',  'Virement', '2025-03-10'],
        [2, 'Netflix Abonnement',                   15.99,  'out', 'Paiement', '2025-03-05'],
        [2, 'Prime de performance',               1200.00, 'in',  'Virement', '2025-02-15'],
        [2, 'Loyer studio',                        750.00,  'out', 'Paiement', '2025-02-01'],
        [3, 'Freelance Projet Web',               1800.00, 'in',  'Virement', '2025-03-12'],
        [3, 'EDF Électricité',                     120.00,  'out', 'Paiement', '2025-03-08'],
        [3, 'Mission consulting — Q1',            3500.00, 'in',  'Virement', '2025-02-28'],
        [3, 'Abonnement Adobe',                     59.99,  'out', 'Paiement', '2025-02-20'],
    ];
    for (const tx of txData) insertTx.run(...tx);
    console.log('✅ Base de données initialisée.');
}

// ─── FONCTION — Envoyer un événement au Guardian Python ────
async function sendToGuardian(event) {
    try {
        await fetch(`${GUARDIAN_URL}/event`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(event)
        });
    } catch (err) {
        console.warn(`[Guardian] Indisponible : ${err.message}`);
    }
}

// ─── PATTERNS SQLi/XSS ─────────────────────────────────────
const WAF_PATTERNS = [
    "' OR", "OR 1=1", "--", "DROP TABLE", "UNION SELECT",
    "<script>", "alert(", "../etc", "SLEEP(", "BENCHMARK("
];

function detectWafPattern(text) {
    if (!text) return null;
    const upper = text.toUpperCase();
    return WAF_PATTERNS.find(p => upper.includes(p.toUpperCase())) || null;
}

const BOT_AGENTS = [
    "curl", "python-requests", "wget", "scrapy",
    "httpclient", "go-http", "libwww", "nmap"
];

function detectBot(userAgent) {
    if (!userAgent) return true;
    return BOT_AGENTS.some(b => userAgent.toLowerCase().includes(b));
}

// ─── MIDDLEWARE PRINCIPAL ──────────────────────────────────
app.use((req, res, next) => {
    const ip      = req.headers['cf-connecting-ip']
                 || req.headers['x-forwarded-for']
                 || req.socket.remoteAddress
                 || 'unknown';
    const country   = req.headers['cf-ipcountry'] || 'XX';
    const userAgent = req.headers['user-agent'] || '';

    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} — IP: ${ip} (${country})`);

    if (detectBot(userAgent)) {
        sendToGuardian({ type: 'bot', ip, country, path: req.path, userAgent, timestamp: Date.now() });
    }

    const toCheck = [req.query.q, req.body?.email, req.body?.password, req.body?.name, req.path].join(' ');
    const pattern = detectWafPattern(toCheck);
    if (pattern) {
        sendToGuardian({ type: 'waf', ip, country, path: req.path, pattern, payload: toCheck.slice(0, 200), timestamp: Date.now() });
    }

    sendToGuardian({ type: 'request', ip, country, path: req.path, method: req.method, userAgent, timestamp: Date.now() });
    next();
});

// ─── ROUTES ────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password);
    if (user) {
        res.json({ success: true, message: `Bienvenue, ${user.name} !`, userId: user.id, userName: user.name });
    } else {
        res.status(401).json({ success: false, message: 'Identifiants incorrects.' });
    }
});

// ⚠️ VOLONTAIREMENT VULNÉRABLE à la SQLi
app.get('/api/search', (req, res) => {
    const query = req.query.q || '';
    const userId = req.query.userId || null;

    let sql;
    if (userId) {
        sql = `SELECT * FROM transactions WHERE user_id = ${userId} AND (label LIKE '%${query}%' OR category LIKE '%${query}%') ORDER BY date DESC`;
    } else {
        sql = `SELECT * FROM transactions WHERE label LIKE '%${query}%' OR category LIKE '%${query}%' ORDER BY date DESC`;
    }
    console.log(`[SQL] ${sql}`);
    try {
        const results = db.prepare(sql).all();
        res.json({ success: true, query, count: results.length, results, sql_executed: sql });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message, query });
    }
});

app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
        return res.status(400).json({ success: false, message: 'Tous les champs sont requis.' });
    try {
        const result = db.prepare(`INSERT INTO users (email, password, name) VALUES (?, ?, ?)`)
            .run(email, password, name);

        // Crédit de bienvenue de 1000€
        const today = new Date().toISOString().split('T')[0];
        db.prepare(`INSERT INTO transactions (user_id, label, amount, type, category, date) VALUES (?, ?, ?, ?, ?, ?)`)
            .run(result.lastInsertRowid, 'Bonus de bienvenue SecureBank', 1000.00, 'in', 'Virement', today);

        res.json({ success: true, message: 'Compte créé avec succès !', userId: result.lastInsertRowid });
    } catch (err) {
        if (err.message.includes('UNIQUE')) {
            res.status(409).json({ success: false, message: 'Cet email est déjà utilisé.' });
        } else {
            res.status(500).json({ success: false, message: err.message });
        }
    }
});

app.get('/api/account/:id', (req, res) => {
    const userId = req.params.id;
    const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ success: false, message: 'Utilisateur introuvable.' });
    const transactions = db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC').all(userId);
    const totalIn  = transactions.filter(t => t.type === 'in').reduce((s, t)  => s + t.amount, 0);
    const totalOut = transactions.filter(t => t.type === 'out').reduce((s, t) => s + t.amount, 0);
    res.json({ success: true, user, balance: totalIn - totalOut, totalIn, totalOut, transactions });
});

/**
 * POST /api/transfer
 * Effectuer un virement vers un autre utilisateur
 */
app.post('/api/transfer', (req, res) => {
    const { fromUserId, toEmail, amount, label } = req.body;

    if (!fromUserId || !toEmail || !amount || !label)
        return res.status(400).json({ success: false, message: 'Champs manquants.' });

    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0)
        return res.status(400).json({ success: false, message: 'Montant invalide.' });
    if (amountNum > 10000)
        return res.status(400).json({ success: false, message: 'Montant maximum : 10 000 €.' });

    // Vérifier le solde de l'expéditeur
    const senderTxs = db.prepare('SELECT * FROM transactions WHERE user_id = ?').all(fromUserId);
    const balance = senderTxs.reduce((s, t) => t.type === 'in' ? s + t.amount : s - t.amount, 0);

    if (balance < amountNum)
        return res.status(400).json({ success: false, message: `Solde insuffisant. Solde actuel : ${balance.toFixed(2)} €` });

    // Trouver le destinataire
    const recipient = db.prepare('SELECT * FROM users WHERE email = ?').get(toEmail);
    if (!recipient)
        return res.status(404).json({ success: false, message: 'Destinataire introuvable.' });

    const sender = db.prepare('SELECT * FROM users WHERE id = ?').get(fromUserId);
    if (recipient.id === parseInt(fromUserId))
        return res.status(400).json({ success: false, message: 'Vous ne pouvez pas vous virer à vous-même.' });

    const today = new Date().toISOString().split('T')[0];
    const insertTx = db.prepare(`INSERT INTO transactions (user_id, label, amount, type, category, date) VALUES (?, ?, ?, ?, ?, ?)`);

    // Transaction dans une transaction SQLite atomique
    const transfer = db.transaction(() => {
        insertTx.run(fromUserId, `Virement vers ${recipient.name} — ${label}`, amountNum, 'out', 'Virement', today);
        insertTx.run(recipient.id, `Virement reçu de ${sender.name} — ${label}`, amountNum, 'in', 'Virement', today);
    });

    transfer();

    const newBalance = balance - amountNum;
    res.json({
        success: true,
        message: `Virement de ${amountNum.toFixed(2)} € envoyé à ${recipient.name} !`,
        newBalance
    });
});

// ─── DÉMARRAGE ─────────────────────────────────────────────
app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║       SecureBank — Mode Guardian (IDS)       ║');
    console.log('╠══════════════════════════════════════════════╣');
    console.log(`║  🌐  Site     : http://localhost:${PORT}          ║`);
    console.log(`║  🛡️  Guardian : ${GUARDIAN_URL}        ║`);
    console.log('╚══════════════════════════════════════════════╝');
    console.log('');
});
