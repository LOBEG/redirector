const WebSocket = require('ws');
const chalk = require('chalk');
const oauth = require('./oauth'); 

let wss = null;
const clients = new Map();

// Configuration
const HEARTBEAT_INTERVAL_MS = 30000; // 30 seconds
const HEARTBEAT_TIMEOUT_MS = 60000;  // 60 seconds — disconnect if no pong
const MAX_MESSAGE_SIZE = 4096;       // 4KB max message size

let heartbeatTimer = null;

/**
 * Initialize WebSocket server with heartbeat and security
 */
function init(server) {
    wss = new WebSocket.Server({ server, maxPayload: MAX_MESSAGE_SIZE });

    wss.on('connection', (ws, req) => {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        clients.set(ws, { 
            userId: null, 
            ip: ip,
            connectedAt: Date.now(),
            isAlive: true
        });

        console.log(chalk.green(`[WS] Client connected from ${ip}`));

        // Mark connection alive on pong
        ws.on('pong', () => {
            const clientData = clients.get(ws);
            if (clientData) {
                clientData.isAlive = true;
            }
        });

        ws.on('message', (message) => {
            // Enforce message size limit
            if (message.length > MAX_MESSAGE_SIZE) {
                console.warn(chalk.yellow(`[WS] Oversized message from ${ip} (${message.length} bytes) — dropped`));
                return;
            }

            try {
                const data = JSON.parse(message);
                
                if (data.type === 'PING') {
                    ws.send(JSON.stringify({ type: 'PONG' }));
                    return;
                }

                if (data.type === 'AUTH' && data.token) {
                    try {
                        const user = oauth.verifyTokenString(data.token);
                        if (user) {
                            const clientData = clients.get(ws);
                            if (clientData) {
                                clientData.userId = user.id;
                                clientData.username = user.user;
                            }
                        } else {
                            console.warn(chalk.yellow(`[WS] Auth failed: null user for token from ${ip}`));
                        }
                    } catch (authErr) {
                        console.warn(chalk.yellow(`[WS] Auth failed from ${ip}: ${authErr.message}`));
                    }
                }
            } catch (e) {
                console.warn(chalk.yellow(`[WS] Malformed message from ${ip}`));
            }
        });

        ws.on('close', () => {
            clients.delete(ws);
        });

        ws.on('error', (err) => {
            console.error(chalk.red('[WS] Error:'), err.message);
            clients.delete(ws);
        });
    });

    // Start heartbeat interval to detect dead connections
    heartbeatTimer = setInterval(() => {
        if (!wss) return;
        wss.clients.forEach((ws) => {
            const clientData = clients.get(ws);
            if (!clientData || !clientData.isAlive) {
                clients.delete(ws);
                return ws.terminate();
            }
            clientData.isAlive = false;
            ws.ping();
        });
    }, HEARTBEAT_INTERVAL_MS);

    wss.on('close', () => {
        if (heartbeatTimer) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = null;
        }
    });
}

/**
 * Broadcast message to specific User ID
 */
function broadcastToUser(userId, type, payload) {
    if (!wss) return;

    const message = JSON.stringify({ type, payload });
    let sent = 0;

    wss.clients.forEach((client) => {
        const clientData = clients.get(client);
        
        if (client.readyState === WebSocket.OPEN && clientData && clientData.userId === userId) {
            client.send(message);
            sent++;
        }
    });

    return sent;
}

/**
 * Middleware: Attach broadcast capability to the request object.
 */
function middleware(req, res, next) {
    req.broadcast = (message) => {
        if (!wss) return;
        const payload = JSON.stringify(message);
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(payload);
            }
        });
    };

    req.broadcastToUser = (userId, type, payload) => {
        return broadcastToUser(userId, type, payload);
    };

    req.broadcastToSelf = (type, payload) => {
        if (req.user && req.user.id) {
            return broadcastToUser(req.user.id, type, payload);
        }
    };

    next();
}

module.exports = {
    init,
    middleware,
    broadcastToUser
};
