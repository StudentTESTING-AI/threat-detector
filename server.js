const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

// Multer configuration for file uploads
const upload = multer({ dest: 'uploads/' });

// Middleware to parse JSON
app.use(express.json());

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Handle file upload and threat analysis
app.post('/analyze', upload.single('file'), (req, res) => {
    const filePath = req.file.path;

    // Perform threat analysis
    const threatPercentage = detectThreats(filePath);

    // Delete the uploaded file after analysis
    fs.unlink(filePath, (err) => {
        if (err) {
            console.error('Error deleting file:', err);
        }
    });

    // Respond with the percentage of threats found
    res.json({ percentage: threatPercentage });
});

// Basic threat detection function
function detectThreats(filePath) {
    const threatKeywords = ['virus', 'malware', 'phishing', 'ransomware'];
    const fileContent = fs.readFileSync(filePath, 'utf-8').toLowerCase();

    let threatCount = 0;
    threatKeywords.forEach(keyword => {
        if (fileContent.includes(keyword)) {
            threatCount++;
        }
    });

    // Calculate percentage of threats (as a simple example)
    const percentage = (threatCount / threatKeywords.length) * 100;
    return percentage;
}

// Phishing URL detection
app.post('/check-url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        // Dynamically import node-fetch
        const fetch = (await import('node-fetch')).default;

        // Perform basic checks or use a simple heuristic
        const isPhishing = await checkForPhishing(url, fetch);
        res.json({ isPhishing });
    } catch (error) {
        console.error('Error checking URL:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Simple function to check for phishing (this can be expanded or use an API)
async function checkForPhishing(url, fetch) {
    // Example heuristic: Check if URL contains suspicious keywords
    const phishingKeywords = ['login', 'update', 'verify', 'account', 'secure'];
    const urlLower = url.toLowerCase();

    for (const keyword of phishingKeywords) {
        if (urlLower.includes(keyword)) {
            return true;
        }
    }

    // Optionally, perform a request to see if the URL behaves suspiciously
    try {
        const response = await fetch(url, { method: 'HEAD' });

        // Check for suspicious response codes or redirects
        if (response.status >= 400 || response.headers.get('location')) {
            return true;
        }
    } catch (error) {
        // If the request fails, it might be a phishing attempt
        return true;
    }

    return false;
}

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
