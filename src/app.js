const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const app = express();
const fs = require('fs');
const https = require('https');
const { Pool } = require('pg');
require('dotenv').config();

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); 

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false 
    }
});

/*  
    Tablica za spremanje povjerljivih podataka za Sensitive data exposure dio zadatka.
*/
async function createTable() {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS sensitiveData (
        id SERIAL PRIMARY KEY,
        data TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `;
  
    try {
      await pool.query(createTableQuery);
      console.log("Table 'sensitiveData' created successfully or already exists.");
    } catch (error) {
      console.error("Error creating table:", error);
    } finally {
      await pool.end(); 
    }
}

let texts = [];          
let isVulnerable = false; 
let isSdeVulnerable = false;

/*
    EncodeData je funkcija za enkodiranje povjerljivih podataka.
    SanitizeText je funkcija za provođenje sanitizacije teksta i zamjene znakova < i > kako se ne bi izvršio kod koji se možda nalazi unutar tagova.
 */
function encodeData(data) {
    return Buffer.from(data).toString('base64');
}

function sanitizeText(text) {
    return text
        .replace(/</g, "&lt;")  
        .replace(/>/g, "&gt;"); 
}
/*
    Htjela sam kreirati document.cookie koji bi se pri XSS napadu mogao ukrasti, ali nisam ga uspjela uopće kreirati.
*/

app.get('/', (req, res) => {
    res.cookie('session_id', '111111', { maxAge: 900000, httpOnly: false, secure: false, sameSite: 'None' });
    res.sendFile(__dirname + '/public/index.html');
});

/*
    Endpoint set-vulnerability služi aplikaciji da definira je li korisniku omogućena ranjivost na XSS napad.
    Endpoint set-sde-vulnerability radi isto za nesigurnu pohranu osjetljivih podataka.
*/

app.post('/set-vulnerability', (req, res) => {
    isVulnerable = req.body.vulnerable;
    console.log(`XSS vulnerability is now ${isVulnerable ? 'enabled' : 'disabled'}.`);
    res.sendStatus(200);
});

app.post('/set-sde-vulnerability', (req, res) => {
    isSdeVulnerable = req.body.vulnerable;
    console.log(`SDE vulnerability is now ${isSdeVulnerable ? 'enabled' : 'disabled'}.`);
    res.sendStatus(200);
})

/*
    Submit-text je endpoint koji se poziva kad se upiše tekst u polje i, na temelju omogućene ili onemogućene ranjivosti, pohranjuje obični ili
    sanitizirani tekst u texts[].
    Submit-data je endpoint koji se poziva kad se upišu osjetljivi podaci u polje i, na temelju omogućene ili onemogućene ranjivosti, pohranjuje 
    te podatke u bazu u enkodiranom ili izvornom obliku.
*/
app.post('/submit-text', (req, res) => {
    const text = req.body.text;

    const sanitizedText = isVulnerable ? text : sanitizeText(text);
    texts.push(sanitizedText);

    res.sendStatus(200); 
});

app.post('/submit-data', async (req, res) => {
    const data = req.body.data;
    const storedData = isSdeVulnerable ? data : encodeData(data);

    try {
        await pool.query('INSERT INTO sensitiveData (data) VALUES ($1)', [storedData]);
        res.sendStatus(200);
    } catch (error) {
        console.error('Error saving data: ', error);
        res.sendStatus(500);
    }
})

/*
    Texts je endpoint za dohvaćanje pohranjenih tekstova u kontekstu XSS napada.
    Fetch-data je endpoint za dohvaćanje osjetljivih podataka iz baze.
*/

app.get('/texts', (req, res) => {
    const textsHTML = texts.map(text => isVulnerable ? text : `<p>${text}</p>`).join('');
    res.send(textsHTML);
});

app.get('/fetch-data', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sensitiveData');
        const dataEntries = result.rows.map(row => ({
            id: row.id,
            data:row.data,
            createdAt: row.created_at
        }));
        res.json(dataEntries);
    } catch (error) {
        console.error('Error fetching data:', error);
        res.sendStatus(500);
    }
})

const port = 3001;

https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
    }, app)
    .listen(port, function () {
    console.log(`Server running at https://localhost:${port}/`);
});


