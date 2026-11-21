const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('ssh2');

// --- Configuration ---
const PORT = 2222;
const LOG_FILE = './threat_intel.jsonl';
const FAKE_BANNER = 'OpenSSH_8.2p1 Ubuntu-4ubuntu0.5';

// --- Defensive Safeguards ---
const MAX_CONCURRENT_CONNECTIONS = 500; // Safely below the 1,024 OS limit
const MAX_ATTEMPTS_PER_MINUTE = 15;     // Threshold for the IP Jail
let activeConnections = 0;
const ipTracker = new Map();

// Ensure the host key exists
let hostKey;
try {
    hostKey = fs.readFileSync('./honeypot_rsa');
} catch (err) {
    console.error('[-] Error: honeypot_rsa key not found.');
    process.exit(1);
}

// Write structured JSON data
function logThreat(data) {
    const jsonString = JSON.stringify(data) + '\n';
    fs.appendFileSync(LOG_FILE, jsonString);
}

// --- Core Honeypot Server ---
const server = new Server({
    hostKeys: [hostKey],
    ident: FAKE_BANNER 
}, (client) => {
    const attackerIP = client._sock.remoteAddress.replace(/^.*:/, ''); 

    // ----------------------------------------------------------------
    // DEFENSE LAYER 1: The Circuit Breaker 
    // ----------------------------------------------------------------
    if (activeConnections >= MAX_CONCURRENT_CONNECTIONS) {
        console.log(`[!] Circuit Breaker Active. Dropping ${attackerIP}`);
        return client._sock.destroy(); // Kill raw TCP silently to save CPU
    }

    // ----------------------------------------------------------------
    // DEFENSE LAYER 2: The IP Jail (Rate Limiting)
    // ----------------------------------------------------------------
    const now = Date.now();
    const ipData = ipTracker.get(attackerIP) || { count: 0, firstSeen: now };
    
    // Reset the tracker if a minute has passed
    if (now - ipData.firstSeen > 60000) {
        ipData.count = 0;
        ipData.firstSeen = now;
    }
    
    ipData.count++;
    ipTracker.set(attackerIP, ipData);

    if (ipData.count > MAX_ATTEMPTS_PER_MINUTE) {
        // They are spamming too fast. Drop them instantly to save resources.
        return client._sock.destroy(); 
    }

    // --- Connection Accepted into Tarpit ---
    activeConnections++;
    let connectionClosed = false;
    const sessionId = crypto.randomBytes(4).toString('hex'); 

    console.log(`[+] [${sessionId}] Connection opened by ${attackerIP} (Active: ${activeConnections})`);

    client.on('authentication', (ctx) => {
        const threatData = {
            timestamp: new Date().toISOString(),
            session_id: sessionId,
            ip_address: attackerIP,
            username: ctx.username,
            password: ctx.password || 'N/A',
            auth_method: ctx.method
        };

        logThreat(threatData);
        console.log(`[!] [${sessionId}] [CAPTURED] IP: ${attackerIP} -> User: ${ctx.username} | Pass: ${ctx.password || 'N/A'}`);

        // The Tarpit Mechanism
        setTimeout(() => {
            if (connectionClosed) return; // Prevent crashes if they disconnected early
            if (ctx.method !== 'password') {
                return ctx.reject(['password', 'publickey']); 
            }
            return ctx.reject();
        }, 2000); 
    });

    // --- Memory Cleanup Routine ---
    // Safely decrement our active connection counter no matter how the attacker leaves
    const cleanup = () => {
        if (!connectionClosed) {
            activeConnections--;
            connectionClosed = true;
            console.log(`[-] [${sessionId}] Connection closed by ${attackerIP} (Active: ${activeConnections})`);
        }
    };

    client.on('error', cleanup);
    client.on('end', cleanup);
    client._sock.on('close', cleanup);
});

// --- Server Initialization ---
server.listen(PORT, '0.0.0.0', () => {
    console.log('===================================================');
    console.log(`🛡️  Defensive SSH Honeypot Active`);
    console.log(`📡 Port: ${PORT} | Max Capacity: ${MAX_CONCURRENT_CONNECTIONS} Connections`);
    console.log(`🕵️‍♂️ Spoofed Banner: ${FAKE_BANNER}`);
    console.log(`📂 Logging to: ${LOG_FILE}`);
    console.log(`🛑 IP Jail: Ban aggressive bots > ${MAX_ATTEMPTS_PER_MINUTE} attempts/min`);
    console.log('===================================================');
    console.log('Waiting for inbound threat traffic...');
});