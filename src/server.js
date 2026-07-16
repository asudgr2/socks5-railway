'use strict';

const net = require('node:net');
const http = require('node:http');

const port = parsePort(process.env.PORT);
const username = requireEnv('SOCKS_USERNAME');
const password = requireEnv('SOCKS_PASSWORD');
const allowedIps = parseAllowedIps(process.env.ALLOWED_IPS || '');
const logLevel = normalizeLogLevel(process.env.LOG_LEVEL || 'info');
const authFailures = new Map();
const connections = new Set();
let shuttingDown = false;

const AUTH_WINDOW_MS = 60_000;
const AUTH_MAX_FAILURES = 10;
const AUTH_BLOCK_MS = 5 * 60_000;
const HANDSHAKE_TIMEOUT_MS = 15_000;
const CONNECT_TIMEOUT_MS = 15_000;
const IDLE_TIMEOUT_MS = 10 * 60_000;
const MAX_HANDSHAKE_BUFFER_BYTES = 64 * 1024;

function log(level, event, fields = {}) {
  const levels = { debug: 10, info: 20, warn: 30, error: 40 };
  if (levels[level] < levels[logLevel]) return;
  process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), level, event, ...fields })}\n`);
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set`);
  return value;
}

function parsePort(value) {
  const parsed = Number.parseInt(value || '0', 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) throw new Error('PORT must be a valid TCP port');
  return parsed;
}

function normalizeLogLevel(value) {
  return ['debug', 'info', 'warn', 'error'].includes(value.toLowerCase()) ? value.toLowerCase() : 'info';
}

function normalizeIp(address) {
  if (!address) return '';
  const withoutZone = address.split('%')[0];
  return withoutZone.startsWith('::ffff:') ? withoutZone.slice(7) : withoutZone;
}

function parseAllowedIps(value) {
  return value.split(',').map((item) => item.trim()).filter(Boolean).map((item) => {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d|[12]\d|3[0-2])?$/.test(item)) throw new Error(`Invalid ALLOWED_IPS entry: ${item}`);
    const [ip, prefixText] = item.split('/');
    const numeric = ipv4ToNumber(ip);
    if (numeric === null) throw new Error(`Invalid ALLOWED_IPS entry: ${item}`);
    return { ip, numeric, prefix: prefixText === undefined ? 32 : Number(prefixText) };
  });
}

function ipv4ToNumber(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => octet < 0 || octet > 255)) return null;
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function isAllowed(address) {
  if (allowedIps.length === 0) return true;
  const number = ipv4ToNumber(normalizeIp(address));
  if (number === null) return false;
  return allowedIps.some(({ numeric, prefix }) => {
    if (prefix === 0) return true;
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    return (number & mask) === (numeric & mask);
  });
}

function timingSafeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && require('node:crypto').timingSafeEqual(leftBuffer, rightBuffer);
}

function isBlocked(address) {
  const record = authFailures.get(address);
  return Boolean(record && record.blockedUntil > Date.now());
}

function recordAuthFailure(address) {
  const now = Date.now();
  const record = authFailures.get(address) || { count: 0, windowStarted: now, blockedUntil: 0 };
  if (now - record.windowStarted > AUTH_WINDOW_MS) {
    record.count = 0;
    record.windowStarted = now;
  }
  record.count += 1;
  if (record.count >= AUTH_MAX_FAILURES) record.blockedUntil = now + AUTH_BLOCK_MS;
  authFailures.set(address, record);
}

setInterval(() => {
  const now = Date.now();
  for (const [address, record] of authFailures) {
    if (record.blockedUntil < now && now - record.windowStarted > AUTH_WINDOW_MS) authFailures.delete(address);
  }
}, AUTH_WINDOW_MS).unref();

const healthServer = http.createServer((request, response) => {
  if (request.url === '/health') {
    response.writeHead(shuttingDown ? 503 : 200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ status: shuttingDown ? 'shutting_down' : 'ok' }));
    return;
  }
  response.writeHead(404).end();
});
healthServer.headersTimeout = 5_000;
healthServer.requestTimeout = 5_000;
healthServer.keepAliveTimeout = 5_000;

const server = net.createServer((client) => {
  const remoteAddress = normalizeIp(client.remoteAddress);
  if (!isAllowed(remoteAddress)) {
    log('warn', 'connection_rejected', { reason: 'ip_not_allowed', remoteAddress });
    client.destroy();
    return;
  }
  connections.add(client);
  client.once('close', () => connections.delete(client));
  client.on('error', (error) => {
    log('debug', 'client_socket_error', { remoteAddress, reason: error.code || 'error' });
  });
  client.once('data', (firstChunk) => {
    client.unshift(firstChunk);
    if (firstChunk[0] === 0x47) {
      healthServer.emit('connection', client);
      return;
    }
    client.setTimeout(HANDSHAKE_TIMEOUT_MS, () => client.destroy());
    handleSocksConnection(client, remoteAddress).catch((error) => {
      log('debug', 'connection_error', { remoteAddress, error: error.message });
      client.destroy();
    });
  });
});

server.on('error', (error) => {
  log('error', 'server_error', { error: error.message });
  process.exitCode = 1;
});

async function handleSocksConnection(client, remoteAddress) {
  if (isBlocked(remoteAddress)) {
    log('warn', 'connection_rejected', { reason: 'auth_rate_limited', remoteAddress });
    client.destroy();
    return;
  }
  const reader = new SocketReader(client);
  const greeting = await reader.read(2);
  if (greeting[0] !== 0x05) throw new Error('not_socks5');
  const methods = await reader.read(greeting[1]);
  if (!methods.includes(0x02)) {
    client.write(Buffer.from([0x05, 0xff]));
    return client.end();
  }
  client.write(Buffer.from([0x05, 0x02]));
  const authHeader = await reader.read(2);
  if (authHeader[0] !== 0x01) throw new Error('invalid_auth_version');
  const suppliedUsername = (await reader.read(authHeader[1])).toString('utf8');
  const passwordLength = (await reader.read(1))[0];
  const suppliedPassword = (await reader.read(passwordLength)).toString('utf8');
  if (!timingSafeEqual(suppliedUsername, username) || !timingSafeEqual(suppliedPassword, password)) {
    recordAuthFailure(remoteAddress);
    log('warn', 'authentication_failed', { remoteAddress });
    client.write(Buffer.from([0x01, 0x01]));
    return client.end();
  }
  authFailures.delete(remoteAddress);
  client.write(Buffer.from([0x01, 0x00]));
  const request = await readRequest(reader);
  if (request.command !== 0x01) {
    reply(client, 0x07);
    return client.end();
  }
  await connectTarget(client, reader, request, remoteAddress);
}

async function readRequest(reader) {
  const header = await reader.read(4);
  if (header[0] !== 0x05 || header[2] !== 0x00) throw new Error('invalid_request');
  let host;
  if (header[3] === 0x01) host = Array.from(await reader.read(4)).join('.');
  else if (header[3] === 0x03) host = (await reader.read((await reader.read(1))[0])).toString('utf8');
  else if (header[3] === 0x04) host = formatIpv6(await reader.read(16));
  else throw new Error('unsupported_address_type');
  const port = (await reader.read(2)).readUInt16BE(0);
  return { command: header[1], host, port };
}

function formatIpv6(buffer) {
  const groups = [];
  for (let index = 0; index < 16; index += 2) groups.push(buffer.readUInt16BE(index).toString(16));
  return groups.join(':');
}

function connectTarget(client, reader, request, remoteAddress) {
  return new Promise((resolve) => {
    const target = net.connect({ host: request.host, port: request.port });
    let settled = false;
    const complete = () => { if (!settled) { settled = true; resolve(); } };
    const timeout = setTimeout(() => target.destroy(new Error('connect_timeout')), CONNECT_TIMEOUT_MS);
    target.once('connect', () => {
      clearTimeout(timeout);
      client.setTimeout(IDLE_TIMEOUT_MS, () => client.destroy());
      target.setTimeout(IDLE_TIMEOUT_MS, () => target.destroy());
      reply(client, 0x00, target.localAddress, target.localPort);
      const remainder = reader.takeRemainder();
      reader.detach();
      if (remainder.length) target.write(remainder);
      client.pipe(target).pipe(client);
      log('info', 'connection_established', { remoteAddress, targetHost: request.host, targetPort: request.port });
      complete();
    });
    target.on('error', (error) => {
      clearTimeout(timeout);
      if (!settled) {
        reply(client, mapConnectError(error));
        client.end();
        log('info', 'connection_failed', { remoteAddress, targetHost: request.host, targetPort: request.port, reason: error.code || 'error' });
        complete();
        return;
      }
      log('debug', 'target_socket_error', { remoteAddress, targetHost: request.host, targetPort: request.port, reason: error.code || 'error' });
      client.destroy();
    });
    client.once('close', () => target.destroy());
  });
}

function mapConnectError(error) {
  if (error.code === 'ECONNREFUSED') return 0x05;
  if (error.code === 'ENETUNREACH') return 0x03;
  if (error.code === 'EHOSTUNREACH') return 0x04;
  return 0x01;
}

function reply(client, status, address = '0.0.0.0', port = 0) {
  const ipv4 = ipv4ToNumber(normalizeIp(address));
  const response = Buffer.alloc(10);
  response[0] = 0x05; response[1] = status; response[2] = 0x00; response[3] = 0x01;
  if (ipv4 !== null) response.writeUInt32BE(ipv4, 4);
  response.writeUInt16BE(port || 0, 8);
  client.write(response);
}

class SocketReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.waiter = null;
    this.onData = (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > MAX_HANDSHAKE_BUFFER_BYTES) socket.destroy(new Error('handshake_buffer_limit_exceeded'));
      this.fulfill();
    };
    this.onClose = () => this.waiter?.reject(new Error('connection_closed'));
    this.onError = (error) => this.waiter?.reject(error);
    socket.on('data', this.onData);
    socket.once('close', this.onClose);
    socket.once('error', this.onError);
  }
  read(length) {
    if (this.buffer.length >= length) return Promise.resolve(this.consume(length));
    return new Promise((resolve, reject) => { this.waiter = { length, resolve, reject }; this.fulfill(); });
  }
  fulfill() {
    if (this.waiter && this.buffer.length >= this.waiter.length) {
      const { length, resolve } = this.waiter;
      this.waiter = null;
      resolve(this.consume(length));
    }
  }
  consume(length) { const result = this.buffer.subarray(0, length); this.buffer = this.buffer.subarray(length); return result; }
  takeRemainder() { const remainder = this.buffer; this.buffer = Buffer.alloc(0); return remainder; }
  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('close', this.onClose);
    this.socket.off('error', this.onError);
  }
}

server.listen(port, '0.0.0.0', () => log('info', 'server_started', { port, allowedIpRules: allowedIps.length }));

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('info', 'shutdown_started', { signal, activeConnections: connections.size });
  server.close(() => process.exit(0));
  for (const socket of connections) socket.end();
  setTimeout(() => { for (const socket of connections) socket.destroy(); process.exit(0); }, 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
