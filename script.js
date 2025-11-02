// Show result box with content
function showResultWithContent(div, html) {
    div.innerHTML = html;
    div.classList.add('has-content');
}

// Hide result box
function hideResult(resultDiv) {
    resultDiv.innerHTML = '';
    resultDiv.classList.remove('has-content');
}

// SHA-256 Hashing
function hashText() {
    const text = document.getElementById('hash-input').value;
    const resultDiv = document.getElementById('hash-result');

    if (text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        crypto.subtle.digest('SHA-256', data).then(hashBuffer => {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
            showResultWithContent(resultDiv, `<strong>SHA-256 Hash:</strong> ${hashHex}`);
        });
    } else {
        showResultWithContent(resultDiv, 'Please enter text to hash.');
    }
}

// Base64 Encoding
function encodeBase64() {
    const inputText = document.getElementById('base64-input').value;
    const resultDiv = document.getElementById('base64-result');

    if (inputText) {
        const encodedText = btoa(inputText);
        showResultWithContent(resultDiv, `<strong>Encoded Base64:</strong> ${encodedText}`);
    } else {
        showResultWithContent(resultDiv, 'Please enter text to encode.');
    }
}

// Base64 Decoding
function decodeBase64() {
    const inputText = document.getElementById('base64-input').value;
    const resultDiv = document.getElementById('base64-result');

    if (inputText) {
        try {
            const decodedText = atob(inputText);
            showResultWithContent(resultDiv, `<strong>Decoded Text:</strong> ${decodedText}`);
        } catch (e) {
            showResultWithContent(resultDiv, '<strong>Error:</strong> Invalid Base64 string');
        }
    } else {
        showResultWithContent(resultDiv, 'Please enter text to decode.');
    }
}

// URL Shortener (using is.gd API)
function shortenUrl() {
    const longUrl = document.getElementById('url-input').value;
    const customUrl = document.getElementById('custom-url').value;
    const resultDiv = document.getElementById('url-result');

    if (!longUrl) {
        showResultWithContent(resultDiv, 'Please enter a URL to shorten.');
        return;
    }

    const existingScript = document.getElementById('jsonp-script');
    if (existingScript) existingScript.remove();

    window.myfunction = function(data) {
        if (data.shorturl) {
            showResultWithContent(resultDiv, `<strong>Shortened URL:</strong> <a href="${data.shorturl}" target="_blank">${data.shorturl}</a>`);
        } else {
            showResultWithContent(resultDiv, `<strong>Error:</strong> ${data.errormessage || 'Unable to shorten URL.'}`);
        }
    };

    const encodedLongUrl = encodeURIComponent(longUrl);
    const encodedCustomUrl = encodeURIComponent(customUrl);
    const apiUrl = `https://is.gd/create.php?format=json&callback=myfunction&url=${encodedLongUrl}&shorturl=${encodedCustomUrl}&logstats=1`;

    const script = document.createElement('script');
    script.src = apiUrl;
    script.id = 'jsonp-script';
    document.body.appendChild(script);
}

// QR Code Generator
function generateQR() {
    const text = document.getElementById('qr-input').value;
    const resultDiv = document.getElementById('qr-result');

    if (text) {
        showResultWithContent(resultDiv, 'Generating QR code...');

        const encodedText = encodeURIComponent(text);
        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodedText}`;

        const testImage = new Image();
        testImage.src = qrUrl;

        testImage.onload = () => {
            showResultWithContent(resultDiv, `<a href="${qrUrl}" target="_blank" class="qr-link">Success! Click here to view</a>`);
        };

        testImage.onerror = () => {
            showResultWithContent(resultDiv, '<strong>Error:</strong> Failed to generate QR code.');
        };
    } else {
        showResultWithContent(resultDiv, 'Please enter text or URL for the QR code.');
    }
}

// IP Geolocation
function performIPGeolocation() {
    const ip = document.getElementById('ip-input').value;
    const resultDiv = document.getElementById('ip-location-result');

    if (ip) {
        showResultWithContent(resultDiv, 'Loading...');

        fetch(`https://ipinfo.io/${ip}/json`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showResultWithContent(resultDiv, `<strong>Error:</strong> ${data.error.message}`);
            } else {
                showResultWithContent(resultDiv, `<strong>Location for IP ${ip}:</strong>
                <pre>City: ${data.city || 'N/A'}</pre>
                <pre>Region: ${data.region || 'N/A'}</pre>
                <pre>Country: ${data.country || 'N/A'}</pre>
                <pre>Location: ${data.loc || 'N/A'}</pre>
                <pre>Organisation: ${data.org || 'N/A'}</pre>
                <pre>Postal Code: ${data.postal || 'N/A'}</pre>`);
            }
        })
        .catch(err => showResultWithContent(resultDiv, `<strong>Error:</strong> ${err}`));
    } else {
        showResultWithContent(resultDiv, 'Please enter an IP address.');
    }
}

// Get User-Agent and Public IP
function getUserAgent() {
    const resultDiv = document.getElementById('user-agent-result');
    const userAgent = navigator.userAgent;

    showResultWithContent(resultDiv, 'Loading...');

    fetch('https://ipinfo.io/json')
    .then(response => response.json())
    .then(data => {
        showResultWithContent(resultDiv, `
        <strong>User-Agent:</strong> ${userAgent}<br>
        <strong>Public IP Address:</strong> ${data.ip}`);
    })
    .catch(err => showResultWithContent(resultDiv, `<strong>Error:</strong> ${err}`));
}

// Discord Webhook Tools
function verifyWebhook() {
    const webhookUrl = document.getElementById('discord-webhook-url').value;
    const resultDiv = document.getElementById('discord-result');

    if (!webhookUrl) {
        showResultWithContent(resultDiv, 'Please enter a webhook URL.');
        return;
    }

    showResultWithContent(resultDiv, 'Verifying webhook...');
    fetch(webhookUrl)
    .then(response => {
        if (response.ok) {
            showResultWithContent(resultDiv, 'Webhook verified successfully.');
        } else {
            showResultWithContent(resultDiv, `<strong>Error:</strong> Invalid webhook or access denied.`);
        }
    })
    .catch(err => showResultWithContent(resultDiv, `<strong>Error:</strong> ${err}`));
}

function sendWebhookMessage() {
    const webhookUrl = document.getElementById('discord-webhook-url').value;
    const message = document.getElementById('discord-message').value;
    const resultDiv = document.getElementById('discord-result');

    if (!webhookUrl) {
        showResultWithContent(resultDiv, 'Please enter a webhook URL.');
        return;
    }

    if (message) {
        showResultWithContent(resultDiv, 'Sending message...');
        fetch(webhookUrl, {
            method: 'POST',
            body: JSON.stringify({ content: message }),
              headers: { 'Content-Type': 'application/json' }
        })
        .then(response => {
            if (response.ok) {
                showResultWithContent(resultDiv, 'Message sent to webhook.');
            } else {
                showResultWithContent(resultDiv, `<strong>Error:</strong> Failed to send message.`);
            }
        })
        .catch(err => showResultWithContent(resultDiv, `<strong>Error:</strong> ${err}`));
    } else {
        showResultWithContent(resultDiv, 'Please enter a message to send.');
    }
}

function spamWebhookMessages() {
    const webhookUrl = document.getElementById('discord-webhook-url').value.trim();
    const rawMessage = document.getElementById('discord-message').value;
    const resultDiv = document.getElementById('discord-result');

    if (!webhookUrl) {
        showResultWithContent(resultDiv, 'Please enter a webhook URL.');
        return;
    }

    const message = rawMessage.trim() || '@everyone raided';
    const formattedMessage = message.replace(/\\n/g, '\n');

    // Ask for send count
    let limitInput = prompt('How many times to send? (0 = unlimited)', '0');
    const limit = limitInput === '0' || !limitInput ? Infinity : parseInt(limitInput);
    if (isNaN(limit) && limit !== Infinity) {
        showResultWithContent(resultDiv, '<strong>Error:</strong> Invalid number.');
        return;
    }

    let sent = 0;
    let isRunning = true;

    // Update UI
    showResultWithContent(resultDiv, `
    <strong>Spamming Webhook...</strong><br>
    <span id="spam-counter">Sent: 0</span><br>
    <span id="spam-status">Starting...</span><br>
    <button onclick="stopSpam()" style="margin-top:8px; background:#ff4444;">Stop Spam</button>
    `);

    window.stopSpam = () => {
        isRunning = false;
        showResultWithContent(resultDiv, `<strong>Stopped by user.</strong> Sent ${sent} message(s).`);
    };

    const counterEl = document.getElementById('spam-counter');
    const statusEl = document.getElementById('spam-status');

    async function sendOne() {
        if (!isRunning) return;
        if (limit !== Infinity && sent >= limit) {
            showResultWithContent(resultDiv, `<strong>Finished!</strong> Sent ${sent} message(s).`);
            return;
        }

        const username = Array.from({length: 80}, () =>
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.charAt(Math.floor(Math.random() * 36))
        ).join('');

        const avatarId = Math.floor(Math.random() * 500) + 1;
        const avatar = `https://picsum.photos/id/${avatarId}/300`;

        const payload = {
            content: formattedMessage,
            username: username,
            avatar_url: avatar,
            tts: false
        };

        try {
            const response = await fetch(webhookUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.status === 204) {
                sent++;
                counterEl.textContent = `Sent: ${sent}`;
                statusEl.textContent = 'Message sent!';
                statusEl.style.color = '#00ff00';
                setTimeout(sendOne, 300); // Small delay for readability
            }
            else if (response.status === 429) {
                const data = await response.json();
                const retryAfter = (data.retry_after || 5) + 1;
                statusEl.textContent = `Rate-limited. Waiting ${retryAfter}s...`;
                statusEl.style.color = '#ff8800';
                setTimeout(sendOne, retryAfter * 1000);
            }
            else {
                const text = await response.text();
                statusEl.textContent = `Failed (code ${response.status})`;
                statusEl.style.color = '#ff0000';
                setTimeout(sendOne, 3000);
            }
        } catch (err) {
            statusEl.textContent = `Error: ${err.message}`;
            statusEl.style.color = '#ff0000';
            setTimeout(sendOne, 3000);
        }
    }

    // Start sending
    sendOne();
}

function deleteWebhook() {
    const webhookUrl = document.getElementById('discord-webhook-url').value;
    const resultDiv = document.getElementById('discord-result');

    if (!webhookUrl) {
        showResultWithContent(resultDiv, 'Please enter a webhook URL.');
        return;
    }

    showResultWithContent(resultDiv, 'Deleting webhook...');
    fetch(webhookUrl, { method: 'DELETE' })
    .then(response => {
        if (response.ok) {
            showResultWithContent(resultDiv, 'Webhook deleted successfully.');
        } else {
            showResultWithContent(resultDiv, '<strong>Error:</strong> Failed to delete webhook.');
        }
    })
    .catch(err => showResultWithContent(resultDiv, `<strong>Error:</strong> ${err}`));
}

// Check Hash Against Wordlist
async function checkHashAgainstWordlist() {
    const hashToCheck = document.getElementById('hash-to-check').value.trim();
    const fileInput = document.getElementById('wordlist-file');
    const resultDiv = document.getElementById('hash-check-result');

    if (!hashToCheck) {
        showResultWithContent(resultDiv, 'Please enter a hash to check.');
        return;
    }

    if (fileInput.files.length === 0) {
        showResultWithContent(resultDiv, 'Please upload a wordlist file.');
        return;
    }

    const file = fileInput.files[0];
    try {
        const wordlist = await handleFileUpload(file);
        let hashFound = false;

        for (const word of wordlist) {
            const wordHash = await generateHash(word);
            if (wordHash === hashToCheck) {
                showResultWithContent(resultDiv, `<strong>Hash found in wordlist:</strong> ${word}`);
                hashFound = true;
                break;
            }
        }

        if (!hashFound) {
            showResultWithContent(resultDiv, 'Hash not found in wordlist.');
        }
    } catch (err) {
        showResultWithContent(resultDiv, `<strong>Error:</strong> ${err}`);
    }
}

// Handle File Upload and Wordlist Parsing
function handleFileUpload(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = function(event) {
            try {
                let wordlist = event.target.result.trim();
                if (file.name.endsWith('.json')) {
                    wordlist = JSON.parse(wordlist);
                    if (!Array.isArray(wordlist)) throw new Error('Invalid JSON format');
                } else if (file.name.endsWith('.txt')) {
                    wordlist = wordlist.split('\n').map(line => line.trim());
                } else {
                    reject('Unsupported file type. Only .txt or .json files are allowed.');
                    return;
                }
                resolve(wordlist);
            } catch (err) {
                reject('Failed to process the file. Ensure it is a valid .txt or .json wordlist.');
            }
        };

        reader.onerror = function() {
            reject('Failed to read the file.');
        };

        reader.readAsText(file);
    });
}

// Generate SHA-256 Hash
async function generateHash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function decodeQRCode() {
    const fileInput = document.getElementById('qr-decoder-file');
    const resultDiv = document.getElementById('qr-decoder-result');

    if (!fileInput.files || fileInput.files.length === 0) {
        showResultWithContent(resultDiv, 'Please select an image file.');
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            if (code) {
                let output = `<strong>Found QR Code:</strong><br>`;
                output += `Data: <code>${escapeHtml(code.data)}</code><br>`;
                output += `Type: ${code.type || 'QRCode'}<br>`;
                output += `Position: x=${code.location.topLeftCorner.x.toFixed(0)}, y=${code.location.topLeftCorner.y.toFixed(0)}<br>`;
                output += `Size: ${Math.round(code.location.bottomRightCorner.x - code.location.topLeftCorner.x)}×${Math.round(code.location.bottomRightCorner.y - code.location.topLeftCorner.y)} px`;

                // Optional: Show image with QR box
                const preview = document.createElement('div');
                preview.innerHTML = `<img src="${e.target.result}" style="max-width:100%; margin-top:10px; border:2px solid #ffbf10;">`;
                resultDiv.innerHTML = output;
                resultDiv.appendChild(preview);
                resultDiv.classList.add('has-content');
            } else {
                showResultWithContent(resultDiv, `
                <strong>No QR code detected.</strong><br>
                <small>Tips:<br>
                • Make sure the QR code is clear and not too small<br>
                • Try increasing contrast or cropping the image</small>
                `);
            }
        };
        img.src = e.target.result;
    };

    reader.onerror = () => showResultWithContent(resultDiv, '<strong>Error:</strong> Failed to read file.');
    reader.readAsDataURL(file);
}

// Helper: escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
