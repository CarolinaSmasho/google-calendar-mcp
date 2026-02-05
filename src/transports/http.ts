import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import http from "http";
import { TokenManager } from "../auth/tokenManager.js";
import { CalendarRegistry } from "../services/CalendarRegistry.js";
import { renderAuthSuccess, renderAuthError, loadWebFile } from "../web/templates.js";
import { ListEventsHandler } from "../handlers/core/ListEventsHandler.js";
import { CreateEventHandler } from "../handlers/core/CreateEventHandler.js";
import { UpdateEventHandler } from "../handlers/core/UpdateEventHandler.js";
import { DeleteEventHandler } from "../handlers/core/DeleteEventHandler.js";
import { CalendarRegistry } from "../services/CalendarRegistry.js";

/**
 * Security headers for HTML responses
 * Note: HTTP mode is designed for localhost development/testing only.
 * For production deployments, use stdio mode with Claude Desktop.
 */
const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-XSS-Protection': '1; mode=block'
};


/**
 * Validate if an origin is from localhost
 * Properly parses the URL to prevent bypass via subdomains like localhost.attacker.com
 * Exported for testing
 */
export function isLocalhostOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    // Only allow exact localhost or 127.0.0.1
    return hostname === 'localhost' || hostname === '127.0.0.1';
  } catch {
    // Invalid URL - reject
    return false;
  }
}

export interface HttpTransportConfig {
  port?: number;
  host?: string;
}

export class HttpTransportHandler {
  private server: McpServer;
  private config: HttpTransportConfig;
  private tokenManager: TokenManager;

  constructor(
    server: McpServer,
    config: HttpTransportConfig = {},
    tokenManager: TokenManager
  ) {
    this.server = server;
    this.config = config;
    this.tokenManager = tokenManager;
  }

  /**
   * Creates an OAuth2Client configured for the given account.
   * Consolidates credential loading and redirect URI construction.
   */
  private async createOAuth2Client(accountId: string, host: string, port: number): Promise<import('google-auth-library').OAuth2Client> {
    const { OAuth2Client } = await import('google-auth-library');
    const { loadCredentials } = await import('../auth/client.js');
    const { client_id, client_secret } = await loadCredentials();
    return new OAuth2Client(
      client_id,
      client_secret,
      `http://${host}:${port}/oauth2callback?account=${accountId}`
    );
  }

  /**
   * Generates an OAuth authorization URL with standard settings.
   */
  private generateOAuthUrl(client: import('google-auth-library').OAuth2Client): string {
    return client.generateAuthUrl({
      access_type: 'offline',
      scope: ['https://www.googleapis.com/auth/calendar'],
      prompt: 'consent'
    });
  }

  /**
   * Validates an account ID format.
   * Throws an error if the format is invalid.
   */
  private async validateAccountId(accountId: string): Promise<void> {
    const { validateAccountId } = await import('../auth/paths.js') as any;
    validateAccountId(accountId);
  }

  private parseRequestBody(req: http.IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => body += chunk.toString());
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch (error) {
          reject(new Error('Invalid JSON in request body'));
        }
      });
      req.on('error', reject);
    });
  }

  async connect(): Promise<void> {
    const port = this.config.port || 3000;
    const host = this.config.host || '127.0.0.1';

    // Configure transport for stateless mode to allow multiple initialization cycles
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined // Stateless mode - allows multiple initializations
    });

    await this.server.connect(transport);

    // Create HTTP server to handle the StreamableHTTP transport
    const httpServer = http.createServer(async (req, res) => {
      // Validate Origin header to prevent DNS rebinding attacks (MCP spec requirement)
      const origin = req.headers.origin;

      // For requests with Origin header, validate it using proper URL parsing
      // This prevents bypass via subdomains like localhost.attacker.com
      if (origin && !isLocalhostOrigin(origin)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Forbidden: Invalid origin',
          message: 'Origin header validation failed'
        }));
        return;
      }

      // Basic request size limiting (prevent DoS)
      const contentLength = parseInt(req.headers['content-length'] || '0', 10);
      const maxRequestSize = 10 * 1024 * 1024; // 10MB limit
      if (contentLength > maxRequestSize) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Payload Too Large',
          message: 'Request size exceeds maximum allowed size'
        }));
        return;
      }

      // Handle CORS - restrict to localhost only for security
      // HTTP mode is designed for local development/testing only
      const allowedCorsOrigin = origin && isLocalhostOrigin(origin)
        ? origin
        : `http://${host}:${port}`;
      res.setHeader('Access-Control-Allow-Origin', allowedCorsOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, mcp-session-id');
      
      if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
      }

      // Validate Accept header for MCP requests (spec requirement)
      if (req.method === 'POST' || req.method === 'GET') {
        const acceptHeader = req.headers.accept;
        if (acceptHeader && !acceptHeader.includes('application/json') && !acceptHeader.includes('text/event-stream') && !acceptHeader.includes('*/*')) {
          res.writeHead(406, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Not Acceptable',
            message: 'Accept header must include application/json or text/event-stream'
          }));
          return;
        }
      }

      // Serve Account Management UI
      if (req.method === 'GET' && (req.url === '/' || req.url === '/accounts')) {
        try {
          const html = await loadWebFile('accounts.html');
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(html);
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to load UI',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // Serve shared CSS
      if (req.method === 'GET' && req.url === '/styles.css') {
        try {
          const css = await loadWebFile('styles.css');
          res.writeHead(200, {
            'Content-Type': 'text/css; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(css);
        } catch (error) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('CSS file not found');
        }
        return;
      }

      // Account Management API Endpoints

      // GET /api/accounts - List all authenticated accounts
      if (req.method === 'GET' && req.url === '/api/accounts') {
        try {
          const accounts = await this.tokenManager.listAccounts();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ accounts }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to list accounts',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // POST /api/accounts - Add new account (get OAuth URL)
      if (req.method === 'POST' && req.url === '/api/accounts') {
        try {
          const body = await this.parseRequestBody(req);
          const accountId = body.accountId;

          if (!accountId || typeof accountId !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'Invalid request',
              message: 'accountId is required and must be a string'
            }));
            return;
          }

          // Validate account ID format
          try {
            await this.validateAccountId(accountId);
          } catch (error) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'Invalid account ID',
              message: error instanceof Error ? error.message : String(error)
            }));
            return;
          }

          // Generate OAuth URL for this account
          const oauth2Client = await this.createOAuth2Client(accountId, host, port);
          const authUrl = this.generateOAuthUrl(oauth2Client);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            authUrl,
            accountId
          }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to initiate OAuth flow',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // GET /oauth2callback - OAuth callback handler
      if (req.method === 'GET' && req.url?.startsWith('/oauth2callback')) {
        try {
          // Use configured host/port instead of req.headers.host for security
          const url = new URL(req.url, `http://${host}:${port}`);
          const code = url.searchParams.get('code');
          const accountId = url.searchParams.get('account');

          if (!code) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Error</h1><p>Authorization code missing</p>');
            return;
          }

          if (!accountId) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Error</h1><p>Account ID missing</p>');
            return;
          }

          // Exchange code for tokens
          const oauth2Client = await this.createOAuth2Client(accountId, host, port);
          const { tokens } = await oauth2Client.getToken(code);

          // Get user email before saving tokens
          oauth2Client.setCredentials(tokens);
          let email = 'unknown';
          try {
            const tokenInfo = await oauth2Client.getTokenInfo(tokens.access_token || '');
            email = tokenInfo.email || 'unknown';
          } catch {
            // Email retrieval failed, continue with 'unknown'
          }

          // Save tokens for this account with cached email
          const originalMode = this.tokenManager.getAccountMode();
          try {
            this.tokenManager.setAccountMode(accountId);
            await this.tokenManager.saveTokens(tokens, email !== 'unknown' ? email : undefined);
          } finally {
            this.tokenManager.setAccountMode(originalMode);
          }

          // Invalidate calendar registry cache since accounts changed
          CalendarRegistry.getInstance().clearCache();

          // Compute allowed origin for postMessage (localhost only)
          const postMessageOrigin = `http://${host}:${port}`;

          const successHtml = await renderAuthSuccess({
            accountId,
            email: email !== 'unknown' ? email : undefined,
            showCloseButton: true,
            postMessageOrigin
          });
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(successHtml);
        } catch (error) {
          const errorHtml = await renderAuthError({
            errorMessage: error instanceof Error ? error.message : String(error),
            showCloseButton: true
          });
          res.writeHead(500, {
            'Content-Type': 'text/html; charset=utf-8',
            ...SECURITY_HEADERS
          });
          res.end(errorHtml);
        }
        return;
      }

      // DELETE /api/accounts/:id - Remove account
      if (req.method === 'DELETE' && req.url?.startsWith('/api/accounts/')) {
        const accountId = req.url.substring('/api/accounts/'.length);

        try {
          // Validate account ID format
          await this.validateAccountId(accountId);

          // Switch to account and clear tokens
          const originalMode = this.tokenManager.getAccountMode();
          try {
            this.tokenManager.setAccountMode(accountId);
            await this.tokenManager.clearTokens();
          } finally {
            this.tokenManager.setAccountMode(originalMode);
          }

          // Invalidate calendar registry cache since accounts changed
          CalendarRegistry.getInstance().clearCache();

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            accountId,
            message: 'Account removed successfully'
          }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to remove account',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // POST /api/accounts/:id/reauth - Re-authenticate account
      if (req.method === 'POST' && req.url?.match(/^\/api\/accounts\/[^/]+\/reauth$/)) {
        const accountId = req.url.split('/')[3];

        try {
          // Validate account ID format
          await this.validateAccountId(accountId);

          // Generate OAuth URL for re-authentication
          const oauth2Client = await this.createOAuth2Client(accountId, host, port);
          const authUrl = this.generateOAuthUrl(oauth2Client);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            authUrl,
            accountId
          }));
        } catch (error) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'Failed to initiate re-authentication',
            message: error instanceof Error ? error.message : String(error)
          }));
        }
        return;
      }

      // Handle health check endpoint
      if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'healthy',
          server: 'google-calendar-mcp',
          timestamp: new Date().toISOString()
        }));
        return;
      }

      // REST API for Frontend - List Events
      if (req.method === 'GET' && (req.url === '/api/events' || req.url?.startsWith('/api/events?'))) {
        try {
          // Check authentication using same logic as manage-accounts
          const accounts = await this.tokenManager.loadAllAccounts();
          if (accounts.size === 0) {
             res.writeHead(401, { 'Content-Type': 'application/json' });
             res.end(JSON.stringify({ error: 'Not authenticated' }));
             return;
          }

          const url = new URL(req.url, `http://${host}:${port}`);
          const timeMin = url.searchParams.get('timeMin') || undefined;
          const timeMax = url.searchParams.get('timeMax') || undefined;
          const calendarId = url.searchParams.get('calendarId') || 'primary'; // Default to primary 
          // Note: Frontend currently assumes it gets events from "primary" or all. 
          // For now, let's default to "primary" if not specified, or we could fetch from all if we want to be smart.
          // But ListEventsHandler expects calendarId.
          
          const handler = new ListEventsHandler();
          // We need to inject CalendarRegistry if it's not a singleton accessed internally by BaseToolHandler?
          // BaseToolHandler uses CalendarRegistry.getInstance(), so we are good.

          // We'll fetch from all accounts if no specific account is requested
          // But ListEventsHandler logic handles account=undefined by merging (if we implemented it that way, let's check).
          // Re-reading ListEventsHandler: "Get clients for specified accounts (supports single or multiple)... merging all events".
          // So passing account: undefined is correct for "all accounts".

          const result = await handler.runTool({
            calendarId: calendarId, // This might need to be 'primary' for each account? 
            // If we pass 'primary', ListEventsHandler will try to find 'primary' calendar on all accounts?
            // ListEventsHandler: "Normalize calendarId... resolveCalendarsToAccounts...".
            // If we pass 'primary', it maps to primary calendar of each account.
            timeMin,
            timeMax,
          }, accounts);

          // The result is CallToolResult { content: [{ type: 'text', text: JSON_STRING }] }
          // We need to parse the text back to JSON to send as response, or just send the text directly.
          if (result.content[0].type === 'text') {
             res.writeHead(200, { 'Content-Type': 'application/json' });
             res.end(result.content[0].text);
          } else {
             throw new Error('Unexpected result format from handler');
          }

        } catch (error) {
           res.writeHead(500, { 'Content-Type': 'application/json' });
           res.end(JSON.stringify({
             error: 'Failed to fetch events',
             message: error instanceof Error ? error.message : String(error)
           }));
        }
        return;
      }

     if (req.method === 'GET' && (req.url?.startsWith('/api/events-range'))) {
         try {
           const accounts = await this.tokenManager.loadAllAccounts();
           if (accounts.size === 0) {
              res.writeHead(401, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Not authenticated' }));
              return;
           }

           const url = new URL(req.url, `http://${host}:${port}`);
           const start = url.searchParams.get('start');
           const end = url.searchParams.get('end');

           if (!start || !end) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Missing start or end parameters' }));
              return;
           }

           const handler = new ListEventsHandler();
           // Fetch from 'primary' calendar of all accounts
           const result = await handler.runTool({
             calendarId: 'primary',
             timeMin: start,
             timeMax: end
           }, accounts);

           if (result.content[0].type === 'text') {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(result.content[0].text);
           } else {
              throw new Error('Unexpected result format from handler');
           }
         } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'Failed to fetch events range',
              message: error instanceof Error ? error.message : String(error)
            }));
         }
         return;
      }

      // POST /api/events - Create new event
      if (req.method === 'POST' && (req.url?.startsWith('/api/events'))) {
         try {
           const accounts = await this.tokenManager.loadAllAccounts();
           if (accounts.size === 0) {
              res.writeHead(401, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Not authenticated' }));
              return;
           }

           const body = await this.parseRequestBody(req);
           const handler = new CreateEventHandler();
           
           // Ensure calendarId is set if not provided (default to primary)
           const args = {
             calendarId: 'primary',
             ...body
           };

           const result = await handler.runTool(args, accounts);

           // CreateEventHandler returns a JSON string in content[0].text
           if (result.content[0].type === 'text') {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(result.content[0].text);
           } else {
              throw new Error('Unexpected result format from handler');
           }
         } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'Failed to create event',
              message: error instanceof Error ? error.message : String(error)
            }));
         }
         return;
      }

       // PATCH /api/events/:eventId - Update event
      if (req.method === 'PATCH' && (req.url?.startsWith('/api/events/') || req.url?.startsWith('/api/events?'))) { 
          // Note: parsing logic needs to be careful about query params vs path path
          // Let's assume /api/events/EVENT_ID pattern for simplicity, or handle both
          
          try {
             const accounts = await this.tokenManager.loadAllAccounts();
             if (accounts.size === 0) {
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Not authenticated' }));
                return;
             }

             const body = await this.parseRequestBody(req);
             
             // Extract eventId from URL if present
             let eventId = body.eventId;
             // Simple regex to extract ID from path if it matches /api/events/ID
             const pathMatch = req.url?.match(/^\/api\/events\/([^/?]+)/);
             if (pathMatch && pathMatch[1]) {
                eventId = pathMatch[1];
             }

             if (!eventId) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Event ID is required' }));
                return;
             }

             const handler = new UpdateEventHandler();
             const args = {
                calendarId: 'primary', // Default
                ...body,
                eventId: eventId
             };

             const result = await handler.runTool(args, accounts);

             if (result.content[0].type === 'text') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(result.content[0].text);
             } else {
                throw new Error('Unexpected result format from handler');
             }

          } catch (error) {
             res.writeHead(500, { 'Content-Type': 'application/json' });
             res.end(JSON.stringify({
               error: 'Failed to update event',
               message: error instanceof Error ? error.message : String(error)
             }));
          }
          return;
      }

      // DELETE /api/events/:eventId - Delete event
      if (req.method === 'DELETE' && (req.url?.startsWith('/api/events/'))) {
         try {
            const accounts = await this.tokenManager.loadAllAccounts();
            if (accounts.size === 0) {
               res.writeHead(401, { 'Content-Type': 'application/json' });
               res.end(JSON.stringify({ error: 'Not authenticated' }));
               return;
            }

            const url = new URL(req.url, `http://${host}:${port}`);
            // Extract ID from path
             const pathParts = url.pathname.split('/');
             // Path is /api/events/ID -> ['', 'api', 'events', 'ID']
             const eventId = pathParts[3];
             const calendarId = url.searchParams.get('calendarId') || 'primary';

             if (!eventId) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Event ID is required' }));
                return;
             }

             const handler = new DeleteEventHandler();
             const result = await handler.runTool({
                calendarId,
                eventId
             }, accounts);

             if (result.content[0].type === 'text') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(result.content[0].text);
             } else {
                throw new Error('Unexpected result format from handler');
             }

         } catch (error) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
               error: 'Failed to delete event',
               message: error instanceof Error ? error.message : String(error)
             }));
         }
         return;
      }

      try {
        await transport.handleRequest(req, res);
      } catch (error) {
        process.stderr.write(`Error handling request: ${error instanceof Error ? error.message : error}\n`);
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: null,
          }));
        }
      }
    });

    httpServer.listen(port, host, () => {
      process.stderr.write(`Google Calendar MCP Server listening on http://${host}:${port}\n`);
    });
  }
} 