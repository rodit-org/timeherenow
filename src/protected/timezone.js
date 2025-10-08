// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// Time Here Now - API Routes

const express = require('express');
const net = require('net');
const router = express.Router();
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
  
  if (format === 'text') {
    res.status(404).type('text/plain').send(errorMessage);
  } else {
    res.status(404).json({ error: errorMessage });
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

  

// Region-specific routes consolidated into /timezone/time via JSON body

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
 * PUT /near-health - NEAR RPC health check endpoint
 */
router.put('/near-health', async (req, res) => {
  try {
    const healthStatus = await timezoneService.nearTimestampService.healthCheck();
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
