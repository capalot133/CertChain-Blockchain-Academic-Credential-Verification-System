import { getRuntimeConfig } from './runtimeConfig';

// Sensitive keys that must be scrubbed from logs/payloads
const SENSITIVE_KEYS = [
    'secret', 'password', 'token', 'authorization', 'private_key', 'key', 'seed', 'jwt', 'email', 'address'
];

/**
 * Recursively scrubs sensitive keys and values from objects before logging
 */
export function scrubSensitiveData(data: unknown): unknown {
    if (!data) return data;
    if (typeof data !== 'object') return data;
    if (Array.isArray(data)) {
        return data.map(scrubSensitiveData);
    }
    const cleanData: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
        if (SENSITIVE_KEYS.some(k => key.toLowerCase().includes(k))) {
            cleanData[key] = '[SCRUBBED]';
        } else if (typeof value === 'object') {
            cleanData[key] = scrubSensitiveData(value);
        } else if (typeof value === 'string' && (value.toLowerCase().startsWith('bearer ') || value.length > 80)) {
            // Also scrub long strings that look like tokens, signatures, or keys
            cleanData[key] = '[SCRUBBED]';
        } else {
            cleanData[key] = value;
        }
    }
    return cleanData;
}

export function isDebugLoggingEnabled(): boolean {
    try {
        const config = getRuntimeConfig();
        return process.env.NODE_ENV !== 'production' && config.debug.enableLogs;
    } catch {
        return false;
    }
}

export function debugLog(...args: unknown[]) {
    if (isDebugLoggingEnabled()) {
        const cleanArgs = args.map(scrubSensitiveData);
        console.log(...cleanArgs);
    }
}

export function debugWarn(...args: unknown[]) {
    if (isDebugLoggingEnabled()) {
        const cleanArgs = args.map(scrubSensitiveData);
        console.warn(...cleanArgs);
    }
}

export function structuredLog(
    level: 'INFO' | 'WARN' | 'ERROR',
    message: string,
    requestId: string,
    context?: Record<string, unknown>
) {
    try {
        const cleanContext = scrubSensitiveData(context);
        const logPayload = {
            timestamp: new Date().toISOString(),
            level,
            requestId,
            message,
            context: cleanContext,
        };

        if (level === 'ERROR') {
            console.error(JSON.stringify(logPayload));
        } else if (level === 'WARN') {
            console.warn(JSON.stringify(logPayload));
        } else {
            console.info(JSON.stringify(logPayload));
        }
    } catch (e) {
        console.error('Error in structuredLog:', e);
    }
}

/**
 * Ingest URL is server-only. A public (NEXT_PUBLIC_*) variant is intentionally
 * not read here: anything in the browser bundle could be used to forge metrics.
 */
function getObservabilityIngestUrl(): string | undefined {
    return process.env.OBSERVABILITY_INGEST_URL;
}

/**
 * Returns the shared secret sent to the ingest endpoint. Server-only.
 */
function getObservabilityIngestSecret(): string | undefined {
    return process.env.OBSERVABILITY_INGEST_SECRET;
}

/**
 * Delivers an observability event. Returns a promise that resolves once the
 * request has completed (or failed), so serverless callers can await it before
 * the function freezes. Failures are logged, never thrown.
 *
 * Authentication uses the `x-observability-secret` header, matching
 * `requireObservabilityIngestRequest` on the receiving side. Without a
 * configured secret no event is sent, so unauthenticated forged metrics
 * cannot be injected.
 */
export async function sendObservabilityEvent(payload: Record<string, unknown>): Promise<void> {
    const ingestUrl = getObservabilityIngestUrl();
    if (!ingestUrl) return;

    const secret = getObservabilityIngestSecret();
    if (!secret) {
        console.error('Observability ingest secret not configured; event not sent.');
        return;
    }

    try {
        const body = JSON.stringify(scrubSensitiveData(payload));
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'x-observability-secret': secret,
        };

        const response = await fetch(ingestUrl, {
            method: 'POST',
            headers,
            body,
            keepalive: true,
        });
        if (!response.ok) {
            console.error('Observability ingest rejected event:', response.status);
        }
    } catch (e) {
        console.error('Error in sendObservabilityEvent:', e);
    }
}

export async function recordMetric(
    name: string,
    value: number,
    context?: Record<string, unknown>
): Promise<void> {
    const payload = {
        timestamp: new Date().toISOString(),
        level: 'INFO',
        event: 'metric',
        metric: name,
        value,
        context: scrubSensitiveData(context),
    };

    console.info(JSON.stringify(payload));
    await sendObservabilityEvent(payload);
}

export async function captureException(error: unknown, context?: Record<string, unknown>): Promise<void> {
    try {
        const cleanContext = scrubSensitiveData(context);
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorStack = error instanceof Error ? error.stack : undefined;

        const payload = {
            timestamp: new Date().toISOString(),
            level: 'FATAL',
            event: 'exception',
            message: errorMessage,
            stack: errorStack,
            context: cleanContext,
        };

        console.error(JSON.stringify(payload));
        await sendObservabilityEvent(payload);
    } catch (e) {
        console.error('Error in captureException:', e);
    }
}
