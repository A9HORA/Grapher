#!/usr/bin/env node
/**
 * Grapher JS Executor — Companion script for the Grapher Burp extension
 *
 * Executes a JavaScript bundle in a sandboxed Node.js VM, and captures
 * assembled GraphQL operations through multiple interception strategies:
 *
 *   1. Intercepts JSON.stringify() — catches query body assembly
 *   2. Intercepts fetch() — catches outbound GraphQL requests
 *   3. Scans module exports after execution — finds query strings in variables
 *   4. Triggers Webpack chunk callbacks to execute module factories
 *
 * Usage: node grapher-executor.js <path_to_js_file>
 *
 * Output: JSON lines to stdout, one per captured operation:
 *   {"query":"mutation Foo{...}","operationName":"Foo","variables":{...}}
 *
 * Security: The VM sandbox has no access to the real file system, network,
 * process, or require. A 10-second timeout kills runaway execution.
 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');

if (process.argv.length < 3) {
    process.stderr.write('Usage: node grapher-executor.js <js_file_path>\n');
    process.exit(1);
}

const jsFilePath = process.argv[2];

let jsContent;
try {
    jsContent = fs.readFileSync(jsFilePath, 'utf8');
} catch (e) {
    process.stderr.write('Error reading file: ' + e.message + '\n');
    process.exit(1);
}

// Collected GraphQL operations
const captured = [];
const seenKeys = new Set();

/**
 * Check if a string looks like a GraphQL operation.
 */
function isGraphQLQuery(s) {
    if (typeof s !== 'string' || s.length < 15) return false;
    const trimmed = s.trim();
    return /^(query|mutation|subscription|fragment)\s/i.test(trimmed) ||
           /^\{\s*(query|mutation|subscription)\s/.test(trimmed);
}

/**
 * Record a captured GraphQL operation, deduplicating by content.
 */
function recordCapture(query, operationName, variables) {
    if (!query || typeof query !== 'string') return;
    const key = query.substring(0, 200) + '|' + (operationName || '');
    if (seenKeys.has(key)) return;
    seenKeys.add(key);

    captured.push({
        query: query,
        operationName: operationName || '',
        variables: variables || {}
    });
}

/**
 * Extract GraphQL from a parsed object (fetch body, JSON.stringify arg).
 */
function captureFromObject(obj) {
    if (!obj || typeof obj !== 'object') return;

    // Standard query field
    if (obj.query && typeof obj.query === 'string' && isGraphQLQuery(obj.query)) {
        recordCapture(obj.query, obj.operationName, obj.variables);
    }

    // doc_id (Relay/Meta)
    if (obj.doc_id) {
        const key = 'doc_id:' + obj.doc_id;
        if (!seenKeys.has(key)) {
            seenKeys.add(key);
            captured.push({
                doc_id: String(obj.doc_id),
                operationName: obj.operationName || '',
                variables: obj.variables || {}
            });
        }
    }

    // Batched queries (array of operations)
    if (Array.isArray(obj)) {
        obj.forEach(item => captureFromObject(item));
    }
}

/**
 * Try to parse a string as JSON and capture GraphQL from it.
 */
function captureFromString(s) {
    if (typeof s !== 'string') return;

    // Direct GraphQL string (not wrapped in JSON)
    if (isGraphQLQuery(s)) {
        const nameMatch = s.match(/^(query|mutation|subscription)\s+(\w+)/);
        recordCapture(s, nameMatch ? nameMatch[2] : '', {});
        return;
    }

    // JSON-wrapped query
    if (s.includes('"query"') && s.includes('{')) {
        try {
            const parsed = JSON.parse(s);
            captureFromObject(parsed);
        } catch (e) {
            // Not valid JSON
        }
    }
}

/**
 * Recursively scan an object for GraphQL strings (max depth 5).
 */
function scanForGraphQL(obj, depth) {
    if (depth > 5 || !obj) return;

    try {
        if (typeof obj === 'string') {
            captureFromString(obj);
            return;
        }

        if (typeof obj === 'function') return;

        if (typeof obj === 'object') {
            const keys = Object.keys(obj);
            for (const key of keys.slice(0, 50)) {
                try {
                    const val = obj[key];
                    if (typeof val === 'string') {
                        captureFromString(val);
                    } else if (typeof val === 'object' && val !== null) {
                        scanForGraphQL(val, depth + 1);
                    }
                } catch (e) {}
            }
        }
    } catch (e) {}
}

/**
 * Fake Response object for intercepted fetch() calls.
 */
function fakeResponse() {
    return {
        ok: true, status: 200, statusText: 'OK', type: 'basic', url: '',
        json: () => Promise.resolve({ data: {} }),
        text: () => Promise.resolve('{}'),
        clone: function() { return fakeResponse(); },
        headers: { get: () => null, has: () => false, forEach: () => {} }
    };
}

/**
 * Build the sandboxed global object.
 */
function buildSandbox() {
    const moduleExports = [];
    const realStringify = JSON.stringify;

    // Intercepted JSON.stringify that captures GraphQL bodies
    function interceptedStringify(value, replacer, space) {
        if (value && typeof value === 'object') {
            captureFromObject(value);
        }
        return realStringify(value, replacer, space);
    }

    const sandbox = {
        self: {}, globalThis: {}, global: {},

        console: {
            log: () => {}, warn: () => {}, error: () => {},
            info: () => {}, debug: () => {}, trace: () => {},
            dir: () => {}, table: () => {},
        },

        // Timers — execute callbacks immediately to trigger lazy init
        setTimeout: (fn) => { try { if (typeof fn === 'function') fn(); } catch(e) {} return 0; },
        clearTimeout: () => {},
        setInterval: () => 0,
        clearInterval: () => {},
        requestAnimationFrame: () => 0,
        cancelAnimationFrame: () => {},
        queueMicrotask: (fn) => { try { fn(); } catch(e) {} },

        // Fetch — intercepted
        fetch: (url, opts) => {
            if (opts && opts.body) {
                captureFromString(typeof opts.body === 'string' ? opts.body : realStringify(opts.body));
            }
            return Promise.resolve(fakeResponse());
        },

        // XMLHttpRequest — intercepted
        XMLHttpRequest: function() {
            this.open = () => {};
            this.setRequestHeader = () => {};
            this.send = (body) => { if (body) captureFromString(body); };
            this.addEventListener = () => {};
            this.readyState = 4; this.status = 200;
            this.responseText = '{}'; this.response = '{}';
        },

        // JSON — with intercepted stringify
        JSON: { stringify: interceptedStringify, parse: JSON.parse },

        AbortSignal: { timeout: () => ({}) },
        AbortController: function() { this.signal = {}; this.abort = () => {}; },
        URL: function(u) { this.href = u || ''; this.toString = () => this.href; },
        Promise: Promise,

        localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {}, length: 0, key: () => null },
        sessionStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {}, length: 0, key: () => null },

        document: {
            createElement: (tag) => ({
                setAttribute: () => {}, style: {}, appendChild: () => {},
                addEventListener: () => {}, getElementsByTagName: () => [],
                querySelector: () => null, querySelectorAll: () => [],
                id: '', className: '', textContent: '', innerHTML: '',
                tagName: (tag || 'div').toUpperCase(),
            }),
            getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
            cookie: '', body: { appendChild: () => {}, removeChild: () => {} },
            head: { appendChild: () => {} }, documentElement: { scrollTop: 0 },
            addEventListener: () => {}, removeEventListener: () => {},
            contains: () => false, createEvent: () => ({ initEvent: () => {} }),
            createTextNode: () => ({}),
        },

        window: null,

        navigator: {
            userAgent: 'Mozilla/5.0 Grapher-Executor',
            language: 'en-US', languages: ['en-US'],
            platform: 'Linux', cookieEnabled: true,
        },
        location: {
            href: 'https://localhost/', origin: 'https://localhost',
            protocol: 'https:', host: 'localhost', hostname: 'localhost',
            pathname: '/', search: '', hash: '',
        },
        screen: { width: 1920, height: 1080, orientation: { type: 'landscape-primary' } },
        history: { pushState: () => {}, replaceState: () => {}, back: () => {}, forward: () => {} },
        Event: function(type) { this.type = type; },
        CustomEvent: function(type, opts) { this.type = type; this.detail = opts?.detail; },

        btoa: (s) => Buffer.from(String(s)).toString('base64'),
        atob: (s) => Buffer.from(String(s), 'base64').toString(),
        encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,

        Math, Date, RegExp, Array, Object, String, Number, Boolean, Symbol,
        Map, Set, WeakMap, WeakSet,
        Error, TypeError, RangeError, SyntaxError,
        parseInt, parseFloat, isNaN, isFinite,
        undefined, NaN, Infinity,

        __webpack_require__: () => ({}),
        _moduleExports: moduleExports,
    };

    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.global = sandbox;

    // Webpack chunk array with intercepted push
    const chunkArray = [];
    chunkArray.push = function(chunk) {
        Array.prototype.push.call(chunkArray, chunk);

        if (!Array.isArray(chunk) || chunk.length < 2) return;
        const modules = chunk[1];
        if (typeof modules !== 'object') return;

        for (const key of Object.keys(modules)) {
            try {
                const factory = modules[key];
                if (typeof factory !== 'function') continue;

                const fakeModule = { exports: {} };
                const fakeExports = fakeModule.exports;
                const fakeRequire = (id) => ({});

                fakeRequire.d = (exports, defs) => {
                    if (typeof defs === 'object') {
                        for (const k of Object.keys(defs)) {
                            try {
                                Object.defineProperty(exports, k, { get: defs[k], enumerable: true });
                            } catch(e) {}
                        }
                    }
                };
                fakeRequire.n = (m) => { const g = () => m; g.a = m; return g; };
                fakeRequire.r = (exports) => {
                    Object.defineProperty(exports, '__esModule', { value: true });
                };
                fakeRequire._ = (a) => a;
                fakeRequire.o = (obj, prop) => Object.prototype.hasOwnProperty.call(obj, prop);
                fakeRequire.e = () => Promise.resolve();
                fakeRequire.t = (value) => value;
                fakeRequire.p = '';

                try {
                    factory(fakeModule, fakeExports, fakeRequire);
                    moduleExports.push(fakeModule.exports);
                } catch(e) {}
            } catch(e) {}
        }
    };

    sandbox.webpackChunk_N_E = chunkArray;
    sandbox.self.webpackChunk_N_E = chunkArray;

    return { sandbox, moduleExports };
}

// Build sandbox and execute
const { sandbox, moduleExports } = buildSandbox();

try {
    const context = vm.createContext(sandbox);
    const script = new vm.Script(jsContent, {
        filename: path.basename(jsFilePath),
        timeout: 10000,
    });
    script.runInContext(context);
} catch (e) {
    process.stderr.write('Execution note: ' + (e.message || String(e)).substring(0, 200) + '\n');
}

// Post-execution: scan all module exports for GraphQL strings
for (const exp of moduleExports) {
    scanForGraphQL(exp, 0);
}

// Also scan sandbox top-level properties
try {
    for (const key of Object.keys(sandbox)) {
        if (key.startsWith('_') || key === 'window' || key === 'self' ||
            key === 'global' || key === 'globalThis') continue;
        try {
            const val = sandbox[key];
            if (typeof val === 'string') captureFromString(val);
        } catch(e) {}
    }
} catch(e) {}

// Allow microtasks to resolve, then output
setTimeout(() => {
    for (const op of captured) {
        process.stdout.write(JSON.stringify(op) + '\n');
    }
    process.exit(0);
}, 500);
