module.exports = function (RED) {
  "use strict";

  const crypto = require("crypto");

  // Some token endpoints sit behind a WAF (e.g. Cloudflare) that answers requests
  // without a User-Agent with an HTML error page instead of the token response.
  const USER_AGENT = "node-red-oauth2-auth/" + require("./package.json").version;

  const TOKEN_REQUEST_TIMEOUT = 30000;
  const MAX_BODY_SNIPPET_LENGTH = 200;

  // Short, single line description of a response body for error messages.
  function describeResponseBody(data) {
    if (data === undefined || data === null || data === "") {
      return "<empty body>";
    }

    var text;

    try {
      text = typeof data === "string" ? data : JSON.stringify(data);
    } catch (e) {
      text = String(data);
    }

    text = text.replace(/\s+/g, " ").trim();

    if (text.length > MAX_BODY_SNIPPET_LENGTH) {
      text = text.substring(0, MAX_BODY_SNIPPET_LENGTH) + "...";
    }

    return text;
  }

  // The "error"/"error_description" pair of an OAuth2 error response (RFC 6749).
  function describeOAuthError(data) {
    if (!data || typeof data !== "object" || !data.error) {
      return null;
    }

    return data.error_description ? data.error + " (" + data.error_description + ")" : String(data.error);
  }

  // Returns a description of what is wrong with a token endpoint response,
  // or null if the response carries a usable access token.
  function getTokenResponseError(status_code, data) {
    if (status_code < 200 || status_code > 299) {
      return "Token endpoint returned HTTP " + status_code + ": " + (describeOAuthError(data) || describeResponseBody(data));
    }

    if (!data || typeof data !== "object") {
      return "Unexpected response from token endpoint (HTTP " + status_code + "): " + describeResponseBody(data);
    }

    const oauth_error = describeOAuthError(data);

    if (oauth_error) {
      return oauth_error;
    }

    if (typeof data.access_token !== "string" || data.access_token.length === 0) {
      return "Token endpoint response contains no access_token (HTTP " + status_code + ").";
    }

    return null;
  }

  // token(field-name) of RFC 7230, i.e. what is allowed as a header name.
  const HEADER_NAME_PATTERN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

  // Set from the body format instead, so header and body can never disagree.
  const BODY_HEADERS = ["content-type", "content-length"];

  // Parses the extra headers of the client config, one "Name: Value" per line.
  // Returns the headers, or throws with the offending line.
  function parseExtraHeaders(text) {
    const headers = [];

    if (!text) {
      return headers;
    }

    const lines = String(text).split(/\r?\n/);

    for (var i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      if (line.length === 0 || line.startsWith("#")) {
        continue;   // blank line or comment
      }

      const separator = line.indexOf(":");
      const name = separator > 0 ? line.substring(0, separator).trim() : "";
      const value = separator > 0 ? line.substring(separator + 1).trim() : "";

      if (!HEADER_NAME_PATTERN.test(name)) {
        throw new Error("Line " + (i + 1) + " is not a valid 'Name: Value' header: " + line);
      }

      if (BODY_HEADERS.indexOf(name.toLowerCase()) !== -1) {
        throw new Error("Line " + (i + 1) + ": " + name + " is set from the body format, remove it from the extra headers.");
      }

      if (/[\x00-\x1F\x7F]/.test(value)) {
        throw new Error("Line " + (i + 1) + ": " + name + " has a value with control characters.");
      }

      headers.push([name, value]);
    }

    return headers;
  }

  // Headers of a token request: the defaults, overridden by the extra headers
  // of the client config (case insensitively, so "accept: ..." replaces the
  // default Accept instead of being sent next to it).
  function buildTokenRequestHeaders(credentials) {
    const headers = new Headers({
      "User-Agent": USER_AGENT,
      "Content-Type": credentials.body_format === "json" ? "application/json" : "application/x-www-form-urlencoded",
      "Accept": "application/json"
    });

    parseExtraHeaders(credentials.extra_headers).forEach(function (header) {
      headers.set(header[0], header[1]);
    });

    return headers;
  }

  // Description of a failed request (no response at all) for error messages.
  function describeRequestError(err) {
    if (err && err.name === "TimeoutError") {
      return "No response from token endpoint within " + TOKEN_REQUEST_TIMEOUT + " ms.";
    }

    // fetch wraps the underlying network error (DNS, TLS, refused) in `cause`.
    if (err && err.cause && err.cause.message) {
      return err.message + " (" + err.cause.message + ")";
    }

    return err && err.message ? err.message : String(err);
  }

  // POSTs a token request and returns { status_code, data }, where data is the
  // parsed JSON body or, if it is not JSON, the raw text.
  async function postTokenRequest(credentials, form) {
    const response = await fetch(credentials.access_token_url, {
      method: "POST",
      headers: buildTokenRequestHeaders(credentials),
      body: credentials.body_format === "json" ? JSON.stringify(form) : new URLSearchParams(form),
      signal: AbortSignal.timeout(TOKEN_REQUEST_TIMEOUT)
    });

    const text = await response.text();

    var data;

    try {
      data = JSON.parse(text);
    } catch (e) {
      data = text;   // e.g. the HTML error page of a WAF
    }

    return { status_code: response.status, data: data };
  }

  // Expiry as absolute time in seconds, or null if the response does not tell us.
  function getExpireTime(data, now) {
    const expires_in = Number(data.expires_in);

    if (!Number.isFinite(expires_in) || expires_in <= 0) {
      return null;
    }

    return { expires_in: expires_in, expire_time: now + expires_in };
  }

  function OAuth2AuthConfig(config) {
    RED.nodes.createNode(this, config);
  }

  RED.nodes.registerType("oauth2-auth-config", OAuth2AuthConfig);

  function OAuth2Auth(config) {
    RED.nodes.createNode(this, config);

    var node = this;
   
    node.on('input', function (msg) {
      node.status({ fill: "blue", shape: "dot", text: RED._("oauth2auth.status.refreshing") });

      node.refreshNodeCredentials((err) => {
        node.status({});

        if (err) {
          node.status({ fill: "red", shape: "dot", text: RED._("oauth2auth.status.failed") });
          return node.error(err);
        }

        const creds = RED.nodes.getCredentials(node.id);

        if (!creds || !creds.access_token) {
          return node.error(RED._("OAuth2Auth.error.no_access_token"));
        }

        msg.headers = {
          Authorization: 'Bearer ' + creds.access_token
        };

        node.send(msg);
      });
    });
  }

  RED.nodes.registerType("oauth2-auth", OAuth2Auth, {
    credentials: {
      client_id: { type: "text" },
      client_secret: { type: "password" },
      access_token_url: { type: "text" },
      body_format: { type: "text" },
      extra_headers: { type: "text" },
      access_token: { type: "password" },
      refresh_token: { type: "password" },
      expire_time: { type: "text" },
      expires_in: { type: "text" },
      auth_time: { type: "text" },
    }
  });

  OAuth2Auth.prototype.refreshNodeCredentials = function (callback) {
    const node = this;

    // Load current creadentials
    const creds = RED.nodes.getCredentials(node.id);

    if (!creds) {
      const err = "No credentials found for OAuth2 node.";
      node.error(RED._("oauth2auth.error.no_credentials", { error: err}));
      return callback(err);
    }

    // Ensure, that the credentials are complete.
    if (!creds.client_id || !creds.client_secret || !creds.refresh_token) {
      const err = "OAuth2 credentials incomplete (missing client_id, client_secret or refresh_token).";
      node.error(RED._("oauth2auth.error.invalid_credentials", { error: err}));
      return callback(err);
    }

    const now = Math.floor(Date.now() / 1000);

    // Is the access token still valid?
    if (creds.expire_time && Number(creds.expire_time) > now) {
        return callback(null);   // Access token is valid
    }

    // Access token is expiured - Perform refresh
    postTokenRequest(creds, {
      grant_type: 'refresh_token',
      client_id: creds.client_id,
      client_secret: creds.client_secret,
      refresh_token: creds.refresh_token
    }).then(function (response) {
      // Only a 2xx response carrying an access token is a successful refresh.
      // Anything else (e.g. an HTML error page from a WAF) must not overwrite
      // the stored credentials.
      const response_error = getTokenResponseError(response.status_code, response.data);

      if (response_error) {
        node.error(RED._("oauth2auth.error.refresh_access_token", { error: response_error }));
        return callback(response_error);
      }

      const data = response.data;
      const expiry = getExpireTime(data, now);

      const newCredentials = {
        ...creds,
        access_token:  data.access_token,
        refresh_token: data.refresh_token || creds.refresh_token,
        expires_in:    expiry ? expiry.expires_in : undefined,
        expire_time:   expiry ? expiry.expire_time : undefined,
        auth_time:     now
      };

      // Store new credentials.
      RED.nodes.addCredentials(node.id, newCredentials);

      return callback(null);
    }, function (err) {
      // Second argument of then(): failures of the handler above must not end
      // up here and call back twice.
      const error = describeRequestError(err);

      node.error(RED._("oauth2auth.error.get_access_token", { error: error }));
      return callback(error);
    });
  }

  RED.httpAdmin.get('/oauth2-auth/auth', function (req, res) {
    if (!req.query.id || !req.query.client_id || !req.query.client_secret || !req.query.authentication_url || !req.query.redirect_url || !req.query.access_token_url) {
      res.send(400);
      return;
    }

    var node_id = req.query.id;
    var client_id = req.query.client_id;
    var client_secret = req.query.client_secret;
    var scope = req.query.scope;
    var force_login = req.query.force_login;
    var authentication_url = req.query.authentication_url;
    var redirect_url = req.query.redirect_url;
    var access_token_url = req.query.access_token_url;
    var body_format = req.query.body_format === "json" ? "json" : "form";
    var extra_headers = req.query.extra_headers || "";
    var csrf_token = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
    var state = node_id + ":" + csrf_token;

    // Reject a broken header list here, before sending the user off to the
    // authorization page for a code that could not be exchanged anyway.
    try {
      parseExtraHeaders(extra_headers);
    } catch (err) {
      return res.status(400).send(RED._("oauth2auth.error.invalid_extra_headers", { error: err.message }));
    }

    var credentials = {
      client_id: client_id,
      client_secret: client_secret,
      redirect_url: redirect_url,
      access_token_url: access_token_url,
      body_format: body_format,
      extra_headers: extra_headers,
      csrf_token: csrf_token
    };

    RED.nodes.addCredentials(node_id, credentials);

    var authentication_url_obj = new URL(authentication_url);
    authentication_url_obj.search = new URLSearchParams({
      client_id: credentials.client_id,
      redirect_uri: redirect_url,
      response_type: 'code',
      state: state,
      scope: scope,
      prompt: force_login.toLowerCase() === "true" ? "login" : "consent"
    });

    res.cookie('csrf', csrf_token);
    res.redirect(authentication_url_obj.href);
  });

  RED.httpAdmin.get('/oauth2-auth/callback', async function (req, res) {
    if (req.query.error) {
      return res.send(RED._("oauth2auth.error.error", { error: req.query.error, description: req.query.error_description }));
    }

    var auth_code = req.query.code;
    var state = req.query.state.split(':');
    var node_id = state[0];
    var credentials = RED.nodes.getCredentials(node_id);

    if (!credentials || !credentials.client_id || !credentials.client_secret) {
      return res.send(RED._("oauth2auth.error.no_credentials"));
    }

    if (state[1] !== credentials.csrf_token) {
      return res.status(401).send(RED._("oauth2auth.error.csrf_token_mismatch"));
    }
   
    var response;

    try {
      response = await postTokenRequest(credentials, {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        redirect_uri: credentials.redirect_url,
      });
    } catch (err) {
      return res.send(RED._("oauth2auth.error.get_access_token", { error: describeRequestError(err) }));
    }

    // Only a 2xx response carrying an access token counts as a successful code
    // exchange. Everything else is reported instead of being stored as an
    // "authorized" node without any token.
    const response_error = getTokenResponseError(response.status_code, response.data);

    if (response_error) {
      return res.send(RED._("oauth2auth.error.something_broke", { error: response_error }));
    }

    const data = response.data;
    const now = Math.floor(Date.now() / 1000);
    const expiry = getExpireTime(data, now);

    credentials.access_token = data.access_token;
    credentials.refresh_token = data.refresh_token;
    credentials.expires_in = expiry ? expiry.expires_in : undefined;
    credentials.expire_time = expiry ? expiry.expire_time : undefined;
    credentials.auth_time = Date.now();

    delete credentials.csrf_token;
    delete credentials.redirect_url;

    RED.nodes.addCredentials(node_id, credentials);

    res.send(RED._("oauth2auth.message.authorisation_successful"));
  });
}
