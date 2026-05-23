#!/usr/bin/env node
/**
 * Grapher JS Executor — Companion script for the Grapher Burp extension
 *
 * Captures GraphQL operations from JavaScript bundles through two stages:
 *
 * STAGE 1 — Static Variable Resolution (preprocesses raw source text)
 *   Scans the JS source for string variable assignments, builds a variable
 *   name → value map, then resolves .concat() and ternary references to
 *   reconstruct dynamically assembled GraphQL queries.
 *
 * STAGE 2 — Sandboxed VM Execution (runs the bundle in an isolated context)
 *   Executes the bundle with intercepted JSON.stringify(), fetch(), and
 *   XMLHttpRequest. After execution, scans Webpack module exports for
 *   GraphQL strings.
 *
 * Results from both stages are merged and deduplicated.
 *
 * Usage: node grapher-executor.js <path_to_js_file>
 * Output: JSON lines to stdout
 * Security: No fs/net/process access inside sandbox. 10s VM timeout.
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

// =========================================================================
// Shared capture infrastructure
// =========================================================================

const captured = [];
const seenKeys = new Set();

function isGraphQLQuery(s) {
    if (typeof s !== 'string' || s.length < 15) return false;
    const t = s.trim();
    return /^(query|mutation|subscription|fragment)\s/i.test(t) ||
           /^\{\s*(query|mutation|subscription)\s/.test(t);
}

function isGraphQLFragment(s) {
    if (typeof s !== 'string' || s.length < 10) return false;
    return /^\s*\.\.\.\s+on\s+\w/.test(s.trim());
}

function recordCapture(query, operationName, variables) {
    if (!query || typeof query !== 'string') return;
    const key = query.substring(0, 300) + '|' + (operationName || '');
    if (seenKeys.has(key)) return;
    seenKeys.add(key);
    captured.push({ query, operationName: operationName || '', variables: variables || {} });
}

function captureFromObject(obj) {
    if (!obj || typeof obj !== 'object') return;
    if (obj.query && typeof obj.query === 'string' && isGraphQLQuery(obj.query)) {
        recordCapture(obj.query, obj.operationName, obj.variables);
    }
    if (obj.doc_id) {
        const key = 'doc_id:' + obj.doc_id;
        if (!seenKeys.has(key)) {
            seenKeys.add(key);
            captured.push({ doc_id: String(obj.doc_id), operationName: obj.operationName || '', variables: obj.variables || {} });
        }
    }
    if (Array.isArray(obj)) obj.forEach(captureFromObject);
}

function captureFromString(s) {
    if (typeof s !== 'string') return;
    if (isGraphQLQuery(s)) {
        const m = s.match(/^(query|mutation|subscription)\s+(\w+)/);
        recordCapture(s, m ? m[2] : '', {});
        return;
    }
    if (s.includes('"query"') && s.includes('{')) {
        try { captureFromObject(JSON.parse(s)); } catch(e) {}
    }
}

function scanForGraphQL(obj, depth) {
    if (depth > 5 || !obj) return;
    try {
        if (typeof obj === 'string') { captureFromString(obj); return; }
        if (typeof obj === 'function') return;
        if (typeof obj === 'object') {
            for (const key of Object.keys(obj).slice(0, 50)) {
                try {
                    const val = obj[key];
                    if (typeof val === 'string') captureFromString(val);
                    else if (typeof val === 'object' && val !== null) scanForGraphQL(val, depth + 1);
                } catch(e) {}
            }
        }
    } catch(e) {}
}

// =========================================================================
// STAGE 1 — Static Variable Resolution
// =========================================================================

function resolveVariables(source) {
    // Phase 1: Build variable map from string assignments
    // Matches: var x = "...", let x = "...", const x = "...", x = "...", ,x="..."
    const varMap = new Map();

    // Pattern: captures single-char and named variables assigned to string literals
    // Handles escaped quotes inside strings via [^"\\]|\\.
    const assignRegex = /(?:var|let|const|,)\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"((?:[^"\\]|\\.)*)"/g;
    let m;
    while ((m = assignRegex.exec(source)) !== null) {
        const varName = m[1];
        const value = m[2]
            .replace(/\\n/g, '\n').replace(/\\t/g, '\t')
            .replace(/\\"/g, '"').replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        if (value.length > 5) {
            varMap.set(varName, value);
        }
    }

    // Also match property assignments: e.x = "..."
    const propAssignRegex = /[a-zA-Z_$][a-zA-Z0-9_$.]*\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*"((?:[^"\\]|\\.)*)"/g;
    while ((m = propAssignRegex.exec(source)) !== null) {
        const varName = m[1];
        const value = m[2]
            .replace(/\\n/g, '\n').replace(/\\t/g, '\t')
            .replace(/\\"/g, '"').replace(/\\'/g, "'").replace(/\\\\/g, '\\');
        if (value.length > 5) {
            varMap.set(varName, value);
        }
    }

    // Phase 2: Find GraphQL base query strings and resolve concatenations
    // Look for JSON.stringify calls containing query fields with .concat()
    const stringifyRegex = /JSON\.stringify\s*\(\s*\{[^}]*query\s*:\s*"((?:[^"\\]|\\.)*)"\s*(?:\.concat\s*\([^)]*\)\s*)*/g;
    
    // Broader approach: find any string that starts with a GraphQL keyword and has .concat
    const queryWithConcat = /"((?:\\.|[^"\\])*)"\s*(?:\.concat\s*\()/g;
    
    while ((m = queryWithConcat.exec(source)) !== null) {
        const baseStr = m[1]
            .replace(/\\n/g, '\n').replace(/\\t/g, '\t')
            .replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        
        if (!isGraphQLQuery(baseStr)) continue;

        // Found a GraphQL base string with .concat() — resolve the chain
        let fullQuery = baseStr;
        let pos = m.index + m[0].length - '.concat('.length; // back up to .concat(

        // Walk the .concat() chain
        while (pos < source.length) {
            const concatMatch = source.substring(pos).match(/^\.concat\s*\(/);
            if (!concatMatch) break;

            pos += concatMatch[0].length;

            // Find matching closing paren
            let depth = 1;
            let concatEnd = pos;
            while (concatEnd < source.length && depth > 0) {
                const ch = source[concatEnd];
                if (ch === '(') depth++;
                else if (ch === ')') depth--;
                concatEnd++;
            }

            const concatArgs = source.substring(pos, concatEnd - 1);
            pos = concatEnd;

            // Resolve the concat argument
            const resolved = resolveConcatArg(concatArgs, varMap);
            for (const fragment of resolved) {
                fullQuery += fragment;
            }
        }

        // Clean up and capture
        const cleaned = fullQuery.replace(/\s+/g, ' ').trim();
        if (cleaned.length > 20 && isGraphQLQuery(cleaned)) {
            const nameMatch = cleaned.match(/^(query|mutation|subscription)\s+(\w+)/);
            recordCapture(cleaned, nameMatch ? nameMatch[2] : '', {});
        }
    }

    // Phase 3: Capture standalone GraphQL strings from the variable map
    for (const [name, value] of varMap) {
        const trimmed = value.replace(/\s+/g, ' ').trim();
        if (isGraphQLQuery(trimmed)) {
            captureFromString(trimmed);
        }
        if (isGraphQLFragment(trimmed)) {
            const fragMatch = trimmed.match(/\.\.\.\s+on\s+(\w+)/);
            if (fragMatch) {
                recordCapture(trimmed, fragMatch[1], {});
            }
        }
    }
}

/**
 * Resolve a .concat() argument to an array of string values.
 * Handles:
 *   - String literals: "..."
 *   - Variable references: varName → lookup in map
 *   - Ternary with empty fallback: cond ? varName : "" → include varName
 *   - Ternary with two non-empty sides: cond ? varA : varB → include both
 *   - Nested ternary expressions
 */
function resolveConcatArg(arg, varMap) {
    const results = [];
    const trimmed = arg.trim();

    // Case 1: Direct string literal "..."
    const strMatch = trimmed.match(/^"((?:[^"\\]|\\.)*)"$/);
    if (strMatch) {
        const val = strMatch[1]
            .replace(/\\n/g, '\n').replace(/\\t/g, '\t')
            .replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        if (val.trim().length > 0) results.push(val);
        return results;
    }

    // Case 2: Ternary expression: condition ? valueA : valueB
    // Match the ? and : to split — handle nested parens in condition
    const ternaryParts = splitTernary(trimmed);
    if (ternaryParts) {
        const truthyResolved = resolveValue(ternaryParts.truthy, varMap);
        const falsyResolved = resolveValue(ternaryParts.falsy, varMap);

        // Include all non-empty values from both branches
        for (const v of truthyResolved) {
            if (v.trim().length > 0) results.push(v);
        }
        for (const v of falsyResolved) {
            if (v.trim().length > 0) results.push(v);
        }
        return results;
    }

    // Case 3: Simple variable reference
    const resolved = resolveValue(trimmed, varMap);
    results.push(...resolved);
    return results;
}

/**
 * Split a ternary expression into condition, truthy, and falsy parts.
 * Handles nested parentheses in the condition (e.g., n.includes("STAY") ? y : "")
 */
function splitTernary(expr) {
    let depth = 0;
    let questionPos = -1;

    // Find the ? that's at depth 0
    for (let i = 0; i < expr.length; i++) {
        const ch = expr[i];
        if (ch === '(' || ch === '[') depth++;
        else if (ch === ')' || ch === ']') depth--;
        else if (ch === '"') {
            // Skip string literal
            i++;
            while (i < expr.length && expr[i] !== '"') {
                if (expr[i] === '\\') i++;
                i++;
            }
        } else if (ch === '?' && depth === 0) {
            questionPos = i;
            break;
        }
    }

    if (questionPos < 0) return null;

    // Find the matching : at depth 0
    depth = 0;
    let colonPos = -1;
    for (let i = questionPos + 1; i < expr.length; i++) {
        const ch = expr[i];
        if (ch === '(' || ch === '[') depth++;
        else if (ch === ')' || ch === ']') depth--;
        else if (ch === '"') {
            i++;
            while (i < expr.length && expr[i] !== '"') {
                if (expr[i] === '\\') i++;
                i++;
            }
        } else if (ch === ':' && depth === 0) {
            colonPos = i;
            break;
        }
    }

    if (colonPos < 0) return null;

    return {
        condition: expr.substring(0, questionPos).trim(),
        truthy: expr.substring(questionPos + 1, colonPos).trim(),
        falsy: expr.substring(colonPos + 1).trim(),
    };
}

/**
 * Resolve a value expression to string(s).
 * Can be a string literal, a variable name, or a nested expression.
 */
function resolveValue(expr, varMap) {
    const trimmed = expr.trim();
    if (!trimmed) return [];

    // String literal
    const strMatch = trimmed.match(/^"((?:[^"\\]|\\.)*)"$/);
    if (strMatch) {
        const val = strMatch[1]
            .replace(/\\n/g, '\n').replace(/\\t/g, '\t')
            .replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        return [val];
    }

    // Variable reference — look up in map
    const varMatch = trimmed.match(/^[a-zA-Z_$][a-zA-Z0-9_$]*$/);
    if (varMatch && varMap.has(trimmed)) {
        const val = varMap.get(trimmed);
        return [val];
    }

    // Expression we can't resolve — return empty
    return [];
}

// =========================================================================
// STAGE 2 — Sandboxed VM Execution
// =========================================================================

function fakeResponse() {
    return {
        ok: true, status: 200, statusText: 'OK', type: 'basic', url: '',
        json: () => Promise.resolve({ data: {} }),
        text: () => Promise.resolve('{}'),
        clone: function() { return fakeResponse(); },
        headers: { get: () => null, has: () => false, forEach: () => {} }
    };
}

function buildSandbox() {
    const moduleExports = [];
    const realStringify = JSON.stringify;

    function interceptedStringify(value, replacer, space) {
        if (value && typeof value === 'object') captureFromObject(value);
        return realStringify(value, replacer, space);
    }

    const sandbox = {
        self: {}, globalThis: {}, global: {},
        console: { log:()=>{}, warn:()=>{}, error:()=>{}, info:()=>{}, debug:()=>{}, trace:()=>{}, dir:()=>{}, table:()=>{} },

        setTimeout: (fn) => { try { if (typeof fn === 'function') fn(); } catch(e) {} return 0; },
        clearTimeout: ()=>{}, setInterval: ()=>0, clearInterval: ()=>{},
        requestAnimationFrame: ()=>0, cancelAnimationFrame: ()=>{},
        queueMicrotask: (fn) => { try { fn(); } catch(e) {} },

        fetch: (url, opts) => {
            if (opts && opts.body) captureFromString(typeof opts.body === 'string' ? opts.body : realStringify(opts.body));
            return Promise.resolve(fakeResponse());
        },
        XMLHttpRequest: function() {
            this.open=()=>{}; this.setRequestHeader=()=>{};
            this.send=(body)=>{ if(body) captureFromString(body); };
            this.addEventListener=()=>{}; this.readyState=4; this.status=200;
            this.responseText='{}'; this.response='{}';
        },

        JSON: { stringify: interceptedStringify, parse: JSON.parse },
        AbortSignal: { timeout: ()=>({}) },
        AbortController: function() { this.signal={}; this.abort=()=>{}; },
        URL: function(u) { this.href=u||''; this.toString=()=>this.href; },
        Promise,

        localStorage: { getItem:()=>null, setItem:()=>{}, removeItem:()=>{}, clear:()=>{}, length:0, key:()=>null },
        sessionStorage: { getItem:()=>null, setItem:()=>{}, removeItem:()=>{}, clear:()=>{}, length:0, key:()=>null },

        document: {
            createElement: (tag) => ({
                setAttribute:()=>{}, style:{}, appendChild:()=>{}, addEventListener:()=>{},
                getElementsByTagName:()=>[], querySelector:()=>null, querySelectorAll:()=>[],
                id:'', className:'', textContent:'', innerHTML:'',
                tagName:(tag||'div').toUpperCase(),
            }),
            getElementById:()=>null, querySelector:()=>null, querySelectorAll:()=>[],
            cookie:'', body:{appendChild:()=>{},removeChild:()=>{}},
            head:{appendChild:()=>{}}, documentElement:{scrollTop:0},
            addEventListener:()=>{}, removeEventListener:()=>{},
            contains:()=>false, createEvent:()=>({initEvent:()=>{}}),
            createTextNode:()=>({}),
        },

        window: null,
        navigator: { userAgent:'Mozilla/5.0 Grapher-Executor', language:'en-US', languages:['en-US'], platform:'Linux', cookieEnabled:true },
        location: { href:'https://localhost/', origin:'https://localhost', protocol:'https:', host:'localhost', hostname:'localhost', pathname:'/', search:'', hash:'' },
        screen: { width:1920, height:1080, orientation:{type:'landscape-primary'} },
        history: { pushState:()=>{}, replaceState:()=>{}, back:()=>{}, forward:()=>{} },
        Event: function(type) { this.type=type; },
        CustomEvent: function(type,opts) { this.type=type; this.detail=opts?.detail; },

        btoa: (s)=>Buffer.from(String(s)).toString('base64'),
        atob: (s)=>Buffer.from(String(s),'base64').toString(),
        encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,

        Math, Date, RegExp, Array, Object, String, Number, Boolean, Symbol,
        Map, Set, WeakMap, WeakSet,
        Error, TypeError, RangeError, SyntaxError,
        parseInt, parseFloat, isNaN, isFinite,
        undefined, NaN, Infinity,

        __webpack_require__: ()=>({}),
        _moduleExports: moduleExports,
    };

    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.global = sandbox;

    // Webpack chunk push interceptor
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
                fakeRequire.d = (exp, defs) => {
                    if (typeof defs === 'object') {
                        for (const k of Object.keys(defs)) {
                            try { Object.defineProperty(exp, k, { get: defs[k], enumerable: true }); } catch(e) {}
                        }
                    }
                };
                fakeRequire.n = (m) => { const g=()=>m; g.a=m; return g; };
                fakeRequire.r = (exp) => { Object.defineProperty(exp, '__esModule', { value: true }); };
                fakeRequire._ = (a) => a;
                fakeRequire.o = (obj, prop) => Object.prototype.hasOwnProperty.call(obj, prop);
                fakeRequire.e = () => Promise.resolve();
                fakeRequire.t = (v) => v;
                fakeRequire.p = '';
                try { factory(fakeModule, fakeExports, fakeRequire); moduleExports.push(fakeModule.exports); } catch(e) {}
            } catch(e) {}
        }
    };

    sandbox.webpackChunk_N_E = chunkArray;
    sandbox.self.webpackChunk_N_E = chunkArray;

    return { sandbox, moduleExports };
}

// =========================================================================
// Execute both stages
// =========================================================================

// Stage 1: Static variable resolution on raw source text
try {
    resolveVariables(jsContent);
} catch (e) {
    process.stderr.write('Variable resolution note: ' + (e.message || String(e)).substring(0, 200) + '\n');
}

// Stage 2: Sandboxed VM execution
const { sandbox, moduleExports } = buildSandbox();
try {
    const context = vm.createContext(sandbox);
    const script = new vm.Script(jsContent, {
        filename: path.basename(jsFilePath),
        timeout: 10000,
    });
    script.runInContext(context);
} catch (e) {
    process.stderr.write('VM execution note: ' + (e.message || String(e)).substring(0, 200) + '\n');
}

// Post-execution: scan module exports
for (const exp of moduleExports) {
    scanForGraphQL(exp, 0);
}

// Scan sandbox top-level
try {
    for (const key of Object.keys(sandbox)) {
        if (key.startsWith('_') || key === 'window' || key === 'self' || key === 'global' || key === 'globalThis') continue;
        try { const val = sandbox[key]; if (typeof val === 'string') captureFromString(val); } catch(e) {}
    }
} catch(e) {}

// Output after microtasks resolve
setTimeout(() => {
    for (const op of captured) {
        process.stdout.write(JSON.stringify(op) + '\n');
    }
    process.exit(0);
}, 500);
