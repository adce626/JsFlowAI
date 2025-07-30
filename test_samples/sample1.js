// Sample JavaScript file for security testing
// This file contains various security vulnerabilities for demonstration

// API endpoints and sensitive data
const API_BASE = 'https://api.example.com';
const SECRET_KEY = 'sk_test_1a2b3c4d5e6f7g8h9i0j';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';

// User management functions
function deleteUser(userId) {
    const endpoint = '/api/users/' + userId + '/delete';
    
    // Vulnerable: No authentication check
    fetch(API_BASE + endpoint, {
        method: 'DELETE',
        headers: {
            'Authorization': 'Bearer ' + SECRET_KEY,
            'Content-Type': 'application/json'
        }
    }).then(response => {
        if (response.ok) {
            // Vulnerable: Using innerHTML without sanitization
            document.getElementById('message').innerHTML = 'User ' + userId + ' deleted successfully';
        }
    });
}

// Admin check function
function isAdmin(user) {
    // Vulnerable: Client-side admin check
    return user.role === 'admin' || user.permissions.includes('admin');
}

// Data processing
function processUserData(data) {
    // Vulnerable: eval() usage
    const result = eval('(' + data + ')');
    
    // Store in localStorage
    localStorage.setItem('userData', JSON.stringify(result));
    
    return result;
}

// Payment processing
const STRIPE_PUBLIC_KEY = 'pk_test_51234567890abcdef';
const paymentEndpoint = '/api/payments/process';

function processPayment(cardData) {
    // Vulnerable: Sending sensitive data in URL
    const url = paymentEndpoint + '?card=' + cardData.number + '&cvv=' + cardData.cvv;
    
    fetch(url, {
        method: 'POST',
        headers: {
            'X-API-Key': STRIPE_PUBLIC_KEY
        }
    });
}

// Message handling
window.addEventListener('message', function(event) {
    // Vulnerable: No origin validation
    if (event.data.type === 'user_data') {
        document.body.innerHTML = event.data.content;
    }
});

// URL redirection
function redirectUser(url) {
    // Vulnerable: Open redirect
    window.location.href = url;
}

// Dynamic script loading
function loadScript(scriptName) {
    // Vulnerable: Dynamic script injection
    const script = document.createElement('script');
    script.src = '/scripts/' + scriptName + '.js';
    document.head.appendChild(script);
}

// Cookie manipulation
function setUserSession(sessionId, userData) {
    // Vulnerable: No secure flag, httpOnly
    document.cookie = 'sessionId=' + sessionId + ';path=/';
    document.cookie = 'userData=' + JSON.stringify(userData) + ';path=/';
}

// Database query (client-side)
function searchUsers(query) {
    // Vulnerable: Potential injection
    const searchEndpoint = '/api/search?q=' + query + '&type=users';
    return fetch(searchEndpoint);
}

// File upload
function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    // Vulnerable: No file type validation
    fetch('/api/upload', {
        method: 'POST',
        body: formData
    });
}
