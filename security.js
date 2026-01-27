// security.js - Anti-hacking measures

class SecuritySystem {
    constructor() {
        this.threatLevel = 0;
        this.blockedIPs = [];
        this.init();
    }
    
    init() {
        this.detectDevTools();
        this.detectNetworkScanning();
        this.detectXSSAttempts();
        this.monitorRequests();
        this.setupHoneypots();
    }
    
    detectDevTools() {
        // Detect if DevTools is open (common for hackers)
        const devtools = /./;
        devtools.toString = function() {
            this.threatLevel += 10;
            console.warn('🚨 Developer Tools detected - Potential security threat');
            return 'devtools_detected';
        };
        
        setInterval(() => {
            console.log(devtools);
            console.clear();
        }, 1000);
    }
    
    detectNetworkScanning() {
        // Monitor for rapid requests
        let requestCount = 0;
        const originalFetch = window.fetch;
        
        window.fetch = function(...args) {
            requestCount++;
            if (requestCount > 10) { // More than 10 requests in short time
                this.threatLevel += 20;
                console.error('🚨 Potential port scanning detected');
            }
            return originalFetch.apply(this, args);
        };
    }
    
    detectXSSAttempts() {
        // Monitor for script injection attempts
        document.addEventListener('DOMNodeInserted', (e) => {
            if (e.target.tagName === 'SCRIPT' && 
                !e.target.src && 
                e.target.innerHTML.includes('<script>')) {
                this.threatLevel += 30;
                e.preventDefault();
                e.stopPropagation();
                this.triggerAlarm('XSS Injection Attempt');
            }
        });
    }
    
    monitorRequests() {
        // Log all AJAX requests
        const originalXHROpen = XMLHttpRequest.prototype.open;
        const originalXHRSend = XMLHttpRequest.prototype.send;
        
        XMLHttpRequest.prototype.open = function(method, url) {
            this._url = url;
            this._method = method;
            
            // Check for suspicious URLs
            const suspiciousPatterns = [
                '/admin', '/config', '/database', 
                '/php', '/asp', '/aspx', '/.env',
                'union select', 'drop table', 'insert into'
            ];
            
            if (suspiciousPatterns.some(pattern => url.includes(pattern))) {
                this.threatLevel += 25;
                this.logSuspiciousActivity(`Suspicious request to: ${url}`);
            }
            
            return originalXHROpen.apply(this, arguments);
        };
        
        XMLHttpRequest.prototype.send = function(body) {
            if (body && typeof body === 'string') {
                // Check for SQL injection in POST data
                const sqlPatterns = [
                    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
                    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
                    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i
                ];
                
                if (sqlPatterns.some(pattern => pattern.test(body))) {
                    this.threatLevel += 40;
                    this.triggerAlarm('SQL Injection Attempt');
                    return; // Block the request
                }
            }
            
            return originalXHRSend.apply(this, arguments);
        };
    }
    
    setupHoneypots() {
        // Create invisible honeypot fields
        setTimeout(() => {
            const honeypot = document.createElement('input');
            honeypot.type = 'text';
            honeypot.name = 'honeypot';
            honeypot.style.display = 'none';
            honeypot.id = 'secret_field';
            honeypot.className = 'hidden';
            
            honeypot.addEventListener('input', () => {
                this.threatLevel += 50;
                this.triggerAlarm('Bot/Hacker detected filling honeypot');
                this.blockUser();
            });
            
            document.body.appendChild(honeypot);
        }, 1000);
    }
    
    logSuspiciousActivity(message) {
        console.error(`🚨 SECURITY ALERT: ${message}`);
        
        // Send to logging service (you need to set this up)
        const logData = {
            message: message,
            threatLevel: this.threatLevel,
            url: window.location.href,
            userAgent: navigator.userAgent,
            timestamp: new Date().toISOString(),
            referrer: document.referrer
        };
        
        // Optional: Send to your logging endpoint
        // fetch('/log-security', {
        //     method: 'POST',
        //     body: JSON.stringify(logData)
        // });
    }
    
    triggerAlarm(reason) {
        alert(`🚨 SECURITY BREACH DETECTED: ${reason}\n\nThis incident has been logged.`);
        
        // Redirect to safe page
        if (this.threatLevel > 50) {
            window.location.href = '/security-alert.html';
        }
    }
    
    blockUser() {
        // Implement blocking logic
        document.body.innerHTML = `
            <div style="background: black; color: red; height: 100vh; display: flex; 
                       justify-content: center; align-items: center; font-family: monospace;">
                <div style="text-align: center;">
                    <h1>⛔ ACCESS TERMINATED ⛔</h1>
                    <p>SECURITY BREACH DETECTED</p>
                    <p>Your activities have been logged</p>
                    <p>IP Address: [REDACTED]</p>
                    <p>Timestamp: ${new Date().toISOString()}</p>
                    <p>Threat Level: ${this.threatLevel}/100</p>
                </div>
            </div>
        `;
        
        // Disable all interaction
        document.onclick = null;
        document.onkeydown = null;
        document.oncontextmenu = null;
    }
}

// Initialize security system
const security = new SecuritySystem();

// Export for use in other files
window.SecuritySystem = SecuritySystem;
