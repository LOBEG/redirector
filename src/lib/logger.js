const chalk = require('chalk');
const fs = require('fs');
const path = require('path');

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLevel = LOG_LEVELS[process.env.LOG_LEVEL || 'info'] || LOG_LEVELS.info;

// --- File Logging Configuration ---
const LOG_DIR = process.env.LOG_DIR || '';
const LOG_MAX_SIZE = parseInt(process.env.LOG_MAX_SIZE, 10) || (10 * 1024 * 1024); // 10MB default
const LOG_MAX_FILES = parseInt(process.env.LOG_MAX_FILES, 10) || 5;

let logStream = null;
let currentLogFile = '';
let currentLogSize = 0;

/**
 * Initialize file-based logging if LOG_DIR is set.
 * Supports basic size-based rotation.
 */
function initFileLogging() {
    if (!LOG_DIR) return;

    try {
        if (!fs.existsSync(LOG_DIR)) {
            fs.mkdirSync(LOG_DIR, { recursive: true });
        }
        currentLogFile = path.join(LOG_DIR, 'app.log');

        // Get current file size
        try {
            const stat = fs.statSync(currentLogFile);
            currentLogSize = stat.size;
        } catch (e) {
            currentLogSize = 0;
        }

        logStream = fs.createWriteStream(currentLogFile, { flags: 'a' });
        logStream.on('error', (err) => {
            console.error('[LOGGER] File write error:', err.message);
            logStream = null;
        });
    } catch (err) {
        console.error('[LOGGER] Failed to init file logging:', err.message);
    }
}

/**
 * Rotate log files when size exceeds limit.
 * app.log -> app.1.log -> app.2.log -> ... -> app.N.log (deleted)
 */
function rotateIfNeeded() {
    if (!LOG_DIR || !logStream || currentLogSize < LOG_MAX_SIZE) return;

    try {
        logStream.end();

        // Shift existing rotated files
        for (let i = LOG_MAX_FILES - 1; i >= 1; i--) {
            const from = path.join(LOG_DIR, `app.${i}.log`);
            const to = path.join(LOG_DIR, `app.${i + 1}.log`);
            try {
                if (fs.existsSync(from)) {
                    if (i + 1 >= LOG_MAX_FILES) {
                        fs.unlinkSync(from); // Delete oldest
                    } else {
                        fs.renameSync(from, to);
                    }
                }
            } catch (fileErr) {
                console.error(`[LOGGER] Failed to rotate app.${i}.log:`, fileErr.message);
            }
        }

        // Rename current to .1
        if (fs.existsSync(currentLogFile)) {
            fs.renameSync(currentLogFile, path.join(LOG_DIR, 'app.1.log'));
        }

        // Open fresh log
        logStream = fs.createWriteStream(currentLogFile, { flags: 'a' });
        currentLogSize = 0;
    } catch (err) {
        console.error('[LOGGER] Rotation error:', err.message);
    }
}

/**
 * Write a line to the log file (if configured).
 */
function writeToFile(plainMessage) {
    if (!logStream) return;
    const line = plainMessage + '\n';
    logStream.write(line);
    currentLogSize += Buffer.byteLength(line);
    rotateIfNeeded();
}

// Initialize on module load
initFileLogging();

const PREFIXES = {
    debug: chalk.gray('[DEBUG]'),
    info:  chalk.blue('[INFO]'),
    warn:  chalk.yellow('[WARN]'),
    error: chalk.red.bold('[ERROR]')
};

/**
 * Safe JSON serialization that handles circular references.
 * @param {*} obj 
 * @returns {string}
 */
function safeStringify(obj) {
    const seen = new WeakSet();
    return JSON.stringify(obj, (key, value) => {
        if (typeof value === 'object' && value !== null) {
            if (seen.has(value)) {
                return '[Circular]';
            }
            seen.add(value);
        }
        return value;
    });
}

function formatMessage(level, module, message, meta) {
    const timestamp = new Date().toISOString();
    const prefix = PREFIXES[level] || '';
    const mod = module ? chalk.cyan(`[${module}]`) : '';
    const base = `${prefix} ${timestamp} ${mod} ${message}`;
    if (meta && Object.keys(meta).length > 0) {
        return `${base} ${chalk.gray(safeStringify(meta))}`;
    }
    return base;
}

function formatPlainMessage(level, module, message, meta) {
    const timestamp = new Date().toISOString();
    const lvl = `[${level.toUpperCase()}]`;
    const mod = module ? `[${module}]` : '';
    const base = `${lvl} ${timestamp} ${mod} ${message}`;
    if (meta && Object.keys(meta).length > 0) {
        return `${base} ${safeStringify(meta)}`;
    }
    return base;
}

function createLogger(module) {
    return {
        debug(message, meta) {
            if (currentLevel <= LOG_LEVELS.debug) {
                console.log(formatMessage('debug', module, message, meta));
                writeToFile(formatPlainMessage('debug', module, message, meta));
            }
        },
        info(message, meta) {
            if (currentLevel <= LOG_LEVELS.info) {
                console.log(formatMessage('info', module, message, meta));
                writeToFile(formatPlainMessage('info', module, message, meta));
            }
        },
        warn(message, meta) {
            if (currentLevel <= LOG_LEVELS.warn) {
                console.warn(formatMessage('warn', module, message, meta));
                writeToFile(formatPlainMessage('warn', module, message, meta));
            }
        },
        error(message, meta) {
            if (currentLevel <= LOG_LEVELS.error) {
                console.error(formatMessage('error', module, message, meta));
                writeToFile(formatPlainMessage('error', module, message, meta));
            }
        }
    };
}

module.exports = createLogger;
