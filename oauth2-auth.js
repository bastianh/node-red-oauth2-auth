module.exports = function (RED) {
  "use strict";

  const crypto = require("crypto");
  const request = require('request');

  // Some token endpoints sit behind a WAF (e.g. Cloudflare) that answers requests
  // without a User-Agent with an HTML error page instead of the token response.
  const USER_AGENT = "node-red-oauth2-auth/" + require("./package.json").version;
  const TOKEN_REQUEST_HEADERS = { "User-Agent": USER_AGENT };

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
  function getTokenResponseError(result, data) {
    const status_code = result && result.statusCode;

    if (typeof status_code === "number" && (status_code < 200 || status_code > 299)) {
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
    request.post({
      url: creds.access_token_url,
      json: true,
      headers: TOKEN_REQUEST_HEADERS,
      form: {
        grant_type: 'refresh_token',
        client_id: creds.client_id,
        client_secret: creds.client_secret,
        refresh_token: creds.refresh_token
      }
    }, 
    function (err, result, data) {
      if (err) {
        node.error(RED._("oauth2auth.error.get_access_token", { error: err }));
        return callback(err);
      }

      // Only a 2xx response carrying an access token is a successful refresh.
      // Anything else (e.g. an HTML error page from a WAF) must not overwrite
      // the stored credentials.
      const response_error = getTokenResponseError(result, data);

      if (response_error) {
        node.error(RED._("oauth2auth.error.refresh_access_token", { error: response_error }));
        return callback(response_error);
      }

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
    var csrf_token = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
    var state = node_id + ":" + csrf_token;

    var credentials = {
      client_id: client_id,
      client_secret: client_secret,
      redirect_url: redirect_url,
      access_token_url: access_token_url,
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

  RED.httpAdmin.get('/oauth2-auth/callback', function (req, res) {
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
   
    request.post({
      url: credentials.access_token_url,
      json: true,
      headers: TOKEN_REQUEST_HEADERS,
      form: {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        redirect_uri: credentials.redirect_url,
      }
    },
      function (err, result, data) {
        if (err) {
          return res.send(RED._("oauth2auth.error.get_access_token", { error: err }));
        }

        // Only a 2xx response carrying an access token counts as a successful
        // code exchange. Everything else is reported instead of being stored as
        // an "authorized" node without any token.
        const response_error = getTokenResponseError(result, data);

        if (response_error) {
          return res.send(RED._("oauth2auth.error.something_broke", { error: response_error }));
        }

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
  });
}
