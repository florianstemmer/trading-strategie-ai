// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const users = [];

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    const existingUser = users.find(user => user.email === email);
    if (existingUser) return res.status(400).json({ error: 'Benutzer existiert bereits' });

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ email, password: hashedPassword, strategies: [] });
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(user => user.email === email);
    if (!user) return res.status(400).json({ error: 'Benutzer nicht gefunden' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ error: 'Falsches Passwort' });

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ token });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.post('/api/generate-strategy', authenticateToken, async (req, res) => {
    const { risk, horizon, experience } = req.body;

    const prompt = `Basierend auf folgenden Trading-Gewohnheiten:
    Risikobereitschaft: ${risk},
    Anlagehorizont: ${horizon},
    Erfahrung: ${experience}.
    Bitte erstelle eine präzise, professionelle Anlagestrategie.`;

    try {
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: "gpt-4",
                messages: [{ role: "user", content: prompt }],
                temperature: 0.7
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                }
            }
        );

        const strategyText = response.data.choices[0].message.content;

        const user = users.find(u => u.email === req.user.email);
        if (user) {
            user.strategies.push({ text: strategyText, createdAt: new Date() });
        }

        res.json({ strategy: strategyText });
    } catch (error) {
        console.error(error.response ? error.response.data : error.message);
        res.status(500).json({ error: "Fehler bei der Erstellung der Strategie" });
    }
});

app.get('/api/my-strategies', authenticateToken, (req, res) => {
    const user = users.find(u => u.email === req.user.email);
    if (!user) return res.sendStatus(404);
    res.json({ strategies: user.strategies });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
