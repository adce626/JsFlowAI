// Advanced JavaScript Security Test Sample
// Contains multiple security vulnerabilities for comprehensive testing

// API Keys and Secrets (CRITICAL RISKS)
const stripeSecretKey = 'sk_live_51234567890abcdefghijk';  // Stripe Live Key - CRITICAL!
const awsAccessKey = 'AKIA1234567890ABCDEF';  // AWS Access Key - CRITICAL!
const googleApiKey = 'AIzaSyDdI0hCZtE6vySjMqM3z9Q8O7X6Y5U4WvN';  // Google API Key
const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// Database Connection String (CRITICAL!)
const mongoConnection = 'mongodb://admin:password123@cluster0.mongodb.net/myapp?retryWrites=true';

// GitHub Token
const githubToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';

// Dangerous Functions - Code Injection Vulnerabilities
function executeUserCode(userInput) {
    // CRITICAL: eval() with user input - Code Injection
    eval(userInput);
    
    // CRITICAL: Function constructor with user input
    new Function(userInput)();
    
    // HIGH: setTimeout with string - Code Injection
    setTimeout(userInput, 1000);
}

// DOM-based XSS Vulnerabilities
function displayUserData(userData) {
    // CRITICAL: innerHTML without sanitization - DOM XSS
    document.getElementById('content').innerHTML = userData;
    
    // HIGH: Direct DOM manipulation with user data
    document.write(userData);
    
    // MEDIUM: Location manipulation
    location.href = userData;
}

// URL Parameter Processing - Open Redirect & XSS
function processUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    const redirectUrl = urlParams.get('redirect');
    const message = urlParams.get('message');
    
    // CRITICAL: Open Redirect vulnerability
    if (redirectUrl) {
        location.href = redirectUrl;  // No validation!
    }
    
    // CRITICAL: DOM XSS from URL parameters
    document.body.innerHTML = '<h1>' + message + '</h1>';
}

// API Endpoints with Security Issues
class APIClient {
    constructor() {
        this.baseUrl = 'https://api.vulnerable-app.com';
        this.adminEndpoint = '/admin/users';  // Privileged endpoint
        this.secretEndpoint = '/api/internal/secrets';  // Internal API
    }
    
    // IDOR Vulnerability - No authorization check
    getUserData(userId) {
        return fetch(`${this.baseUrl}/users/${userId}`, {
            headers: {
                'Authorization': `Bearer ${jwtToken}`,  // Hardcoded token!
                'X-API-Key': googleApiKey  // Exposed API key in client!
            }
        });
    }
    
    // SSRF Vulnerability
    fetchExternalData(externalUrl) {
        // No URL validation - SSRF risk
        return fetch(externalUrl);
    }
    
    // Insecure data transmission
    sendSensitiveData(data) {
        // HTTP instead of HTTPS for sensitive data
        return fetch('http://insecure-endpoint.com/data', {
            method: 'POST',
            body: JSON.stringify(data),
            headers: {
                'Content-Type': 'application/json',
                'X-Secret-Key': stripeSecretKey  // Secret in headers!
            }
        });
    }
}

// Local Storage Security Issues
function handleSensitiveData(userToken, sensitiveInfo) {
    // HIGH: Storing sensitive data in localStorage
    localStorage.setItem('userToken', userToken);
    localStorage.setItem('creditCard', sensitiveInfo.creditCard);
    localStorage.setItem('ssn', sensitiveInfo.ssn);
    
    // Session storage with sensitive data
    sessionStorage.setItem('adminAccess', 'true');
}

// Form Processing with Validation Issues
function processLoginForm() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // MEDIUM: Password in URL (GET request)
    fetch(`/login?username=${username}&password=${password}`);
    
    // Client-side only validation
    if (username === 'admin' && password === 'admin123') {
        // CRITICAL: Client-side authentication
        localStorage.setItem('isAdmin', 'true');
        location.href = '/admin-panel';
    }
}

// Cross-Site Request Forgery (CSRF) Vulnerability
function transferMoney(amount, toAccount) {
    // No CSRF protection
    fetch('/api/transfer', {
        method: 'POST',
        credentials: 'include',  // Includes cookies
        body: JSON.stringify({
            amount: amount,
            to: toAccount
        })
    });
}

// PostMessage Security Issues
window.addEventListener('message', function(event) {
    // CRITICAL: No origin validation
    if (event.data.action === 'executeCode') {
        eval(event.data.code);  // Code injection via postMessage
    }
    
    if (event.data.action === 'updateDOM') {
        // DOM XSS via postMessage
        document.body.innerHTML = event.data.html;
    }
});

// WebSocket Security Issues
const ws = new WebSocket('ws://insecure-websocket.com');  // HTTP instead of HTTPS
ws.onmessage = function(event) {
    // No validation of WebSocket messages
    const data = JSON.parse(event.data);
    document.getElementById('chat').innerHTML += data.message;  // XSS
};

// Prototype Pollution Vulnerability
function mergeObjects(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = mergeObjects(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];  // Prototype pollution risk
        }
    }
    return target;
}

// Additional API endpoints for discovery
const endpoints = [
    '/api/v1/users',
    '/api/v1/payments/process',
    '/admin/dashboard',
    '/api/internal/config',
    'https://external-api.com/data',
    '/webhook/stripe',
    '/oauth/callback'
];

// More secrets in different formats
const config = {
    'stripe_pk': 'pk_test_51234567890abcdefghijk',
    'sendgrid_key': 'SG.1234567890abcdefghijk.1234567890abcdefghijklmnopqrstuvwxyz',
    'mailgun_key': 'key-1234567890abcdef1234567890abcdef',
    'rollbar_token': 'R_1234567890abcdef1234567890abcdef',
    'slack_webhook': 'xoxb-123456789012-123456789012-1234567890abcdefghijklmn'
};

// SQL Injection (simulated for client-side)
function searchUsers(query) {
    // Dangerous: building SQL-like queries on client
    const sqlQuery = `SELECT * FROM users WHERE name = '${query}'`;
    // This would be sent to backend without sanitization
}