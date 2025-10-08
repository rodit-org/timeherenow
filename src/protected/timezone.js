// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// Time Here Now - API Routes

const express = require('express');
const net = require('net');
const router = express.Router();
const base64url = require('base64url');
const sdk = require('../../sdk');
const TimeZoneService = require('../lib/timezone-service');

// Simple logger fallback
const logger = {
  error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta || ''),
  info: (msg, meta) => console.log(`[INFO] ${msg}`, meta || '')
};

// Initialize timezone service
const timezoneService = new TimeZoneService();

  function getClientIP(req) {
    return req.ip || 
          req.connection.remoteAddress || 
          req.socket.remoteAddress ||
          (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
          '0.0.0.0';
  }

  /**
   * Helper to resolve locale from body or Accept-Language header
   */
  function getLocale(req) {
    const bodyLocale = (req.body && req.body.locale) ? String(req.body.locale) : null;
    const headerLocale = req.headers && (req.headers['accept-language'] || req.headers['Accept-Language']);
    return bodyLocale || headerLocale || 'en';
  }

  /**
   * Helper function to handle errors consistently
   */
function handleError(res, error, format = 'json') {
  logger.error('TimeZone API Error:', {
    error: error.message,
    stack: error.stack
  });

  const errorMessage = error.message || 'Internal server error';
  const statusCode = /NEAR time unavailable/i.test(errorMessage) ? 503 : 404;
  
  if (format === 'text') {
    res.status(statusCode).type('text/plain').send(errorMessage);
  } else {
    res.status(statusCode).json({ error: errorMessage });
  }
}

  /**
   * PUT /timezone - List all timezones (JSON)
   */
  router.put('/timezone', async (req, res) => {
    try {
      const timezones = await timezoneService.getAllTimezones();
      res.json(timezones);
    } catch (error) {
      handleError(res, error);
    }
  });

  

  /**
   * PUT /timezone/area - List timezones for specific area (JSON)
   * Body: { area: string }
   */
  router.put('/timezone/area', async (req, res) => {
  try {
    const { area } = req.body || {};
    const timezones = await timezoneService.getTimezonesByArea(area);
    
    if (timezones.length === 0) {
      throw new Error(`Unknown area: ${area}`);
    }
    
    res.json(timezones);
  } catch (error) {
    handleError(res, error);
  }
});

  

/**
 * PUT /timezone/time - Get current time for timezone (JSON)
 * Preferred Body: { timezone: string, locale?: string }
 * Legacy Body (supported as fallback): { area: string, location: string, region?: string, locale?: string }
 */
router.put('/timezone/time', async (req, res) => {
  try {
    const { timezone: tzFromBody, area, location, region } = req.body || {};
    const clientIP = getClientIP(req);
    const locale = getLocale(req);
    let timezone = tzFromBody;
    if (!timezone) {
      if (area && location) {
        // Legacy segmented params
        timezone = await timezoneService.validateTimezoneParams(area, location, region);
      } else {
        // Fallback to user IP derived timezone
        timezone = timezoneService.getTimezoneForIP(clientIP);
      }
    }
    const timeData = await timezoneService.getTimeDataForTimezone(timezone, clientIP, locale);
    res.json(timeData);
  } catch (error) {
    handleError(res, error);
  }
});

  /**
   * PUT /timezones/by-country - List timezones by ISO 3166-1 alpha-2 country code
   * Body: { country_code: string }
   */
  router.put('/timezones/by-country', async (req, res) => {
    try {
      const { country_code } = req.body || {};
      const list = await timezoneService.getTimezonesByCountryCode(country_code);
      if (!list || list.length === 0) {
        throw new Error(`Unknown or unsupported country code: ${country_code}`);
      }
      res.json(list);
    } catch (error) {
      handleError(res, error);
    }
  });

  


/**
 * PUT /ip - Get current time based on the user IP or specified IP (IPv4 or IPv6) (JSON)
 * Body: { ip?: string }
 */
  router.put('/ip', async (req, res) => {
  try {
    const { ip } = req.body || {};
    if (ip && net.isIP(String(ip).trim()) === 0) {
      throw new Error(`Invalid IP address: ${ip}`);
    }
    const sourceIP = ip && String(ip).trim() !== '' ? String(ip).trim() : getClientIP(req);
    const timezone = timezoneService.getTimezoneForIP(sourceIP);
    const locale = getLocale(req);
    const timeData = await timezoneService.getTimeDataForTimezone(timezone, sourceIP, locale);
    
    res.json(timeData);
  } catch (error) {
    handleError(res, error);
  }
});

  

// IP-by-parameter routes consolidated into /ip and /ip.txt via JSON body

/**
 * PUT /sign/hash - Sign provided base64url-encoded hash concatenated with NEAR time, likely diff and public key
 * Body: { hash_b64url: string }
 */
router.put('/sign/hash', async (req, res) => {
  try {
    const { hash_b64url } = req.body || {};
    if (!hash_b64url || typeof hash_b64url !== 'string') {
      return res.status(400).json({ error: 'hash_b64url is required' });
    }
    let hashBytes;
    try {
      hashBytes = base64url.toBuffer(hash_b64url);
    } catch (e) {
      return res.status(400).json({ error: 'hash_b64url must be valid base64url' });
    }
    // Reasonable upper limit for hash input
    if (hashBytes.length === 0 || hashBytes.length > 128) {
      return res.status(400).json({ error: 'hash_b64url decoded length must be between 1 and 128 bytes' });
    }

    // Get latest NEAR status from cache (throws if unavailable)
    const status = timezoneService.getNearStatus();
    const timestamp_iso = status.iso;
    const likely_time_difference_ms = status.likely_time_difference_ms;

    // Get private seed bytes from RoditClient config
    if (!req.app.locals.roditClient || typeof req.app.locals.roditClient.getConfigOwnRodit !== 'function') {
      return res.status(503).json({ error: 'Signing service unavailable' });
    }
    const configObject = await req.app.locals.roditClient.getConfigOwnRodit();
    if (!configObject || !configObject.own_rodit_bytes_private_key) {
      return res.status(503).json({ error: 'Signing key unavailable' });
    }
    const seedBytes = configObject.own_rodit_bytes_private_key;

    // Derive public key and sign using local SDK helpers
    const public_key_base64url = sdk.publicKeyFromSeedBase64url(seedBytes);
    const concatenated = `${hash_b64url}.${timestamp_iso}.${likely_time_difference_ms}.${public_key_base64url}`;
    const signature_base64url = sdk.signBytesBase64urlWithSeed(seedBytes, Buffer.from(concatenated, 'utf8'));

    res.json({
      data: {
        hash_b64url,
        timestamp_iso,
        likely_time_difference_ms,
        public_key_base64url
      },
      concatenated,
      signature_base64url
    });
  } catch (error) {
    // Use existing error handler for NEAR unavailability and others
    if (/NEAR time unavailable/i.test(error.message)) {
      return res.status(503).json({ error: error.message });
    }
    handleError(res, error);
  }
});

/**
 * PUT /near-health - NEAR RPC health check endpoint
 */
router.put('/near-health', async (req, res) => {
  try {
    const healthStatus = await timezoneService.healthCheck();
    res.json(healthStatus);
  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;
