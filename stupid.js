const express = require('express');
const fs = require('fs');
const vm = require('vm');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());

/**
 * 🚨 Vulnerability 1: Insecure Deserialization
 * - Uses `vm.runInNewContext()` to execute user-supplied JavaScript.
 * - Attackers can inject and execute arbitrary code.
 */
app.post('/execute', (req, res) => {
    let userInput = req.body.code;
    try {
        let result = vm.runInNewContext(userInput); // ⚠️ UNSAFE: Executes user-supplied JavaScript code
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: 'Execution failed' });
    }
});

/**
 * 🚨 Vulnerability 2: Server-Side Request Forgery (SSRF)
 * - Allows user-supplied URLs to be fetched without validation.
 * - Attackers can make the server send requests to internal services.
 */
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    const allowedUrls = ['https://example.com/data', 'https://api.example.com/info']; // Define an allow-list of acceptable URLs
    if (allowedUrls.includes(url)) {
        fetch(url) // SAFE: User input is validated against the allow-list
            .then(response => response.text())
            .then(data => res.send(data))
            .catch(err => res.status(500).send('Error fetching URL'));
    } else {
        res.status(400).send('Invalid URL');
    }
});

/**
 * 🚨 Vulnerability 3: Local File Inclusion (LFI)
 * - Uses `fs.readFileSync()` with user input to read files.
 * - Attackers can read sensitive files from the server.
 */
app.get('/readfile', (req, res) => {
    const filename = req.query.filename;
    try {
        const data = fs.readFileSync(filename, 'utf8'); // ⚠️ UNSAFE: Allows path traversal attacks
        res.send(data);
    } catch (error) {
        res.status(500).send('Error reading file');
    }
});

/**
 * 🚨 Vulnerability 4: Hardcoded Credentials
 * - Contains a hardcoded API key, which is a security risk.
 * - If committed to GitHub, Secret Scanning will detect it.
 */
const API_KEY = "sk_test_1234567890abcdef"; // ⚠️ UNSAFE: Hardcoded sensitive secret

// Start the server
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});