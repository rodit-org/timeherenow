// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// Time Here Now - API Routes

const express = require('express');
const router = express.Router();
const TimeZoneService = require('../lib/timezone-service');

// Simple logger fallback
const logger = {
  error: (msg, meta) => console.error(`[ERROR] ${msg}`, meta || ''),
  info: (msg, meta) => console.log(`[INFO] ${msg}`, meta || '')
};

// Initialize timezone service
const timezoneService = new TimeZoneService();

/**
 * Helper function to get client IP
 */
function getClientIP(req) {
  return req.ip || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         '0.0.0.0';
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
router.put('/timezone', (req, res) => {
  try {
    const timezones = timezoneService.getAllTimezones();
    res.json(timezones);
  } catch (error) {
    handleError(res, error);
  }
});

/**
 * PUT /timezone.txt - List all timezones (Plain text)
 */
router.put('/timezone.txt', (req, res) => {
  try {
    const timezones = timezoneService.getAllTimezones();
    const textResponse = timezoneService.formatTimezonesAsText(timezones);
    res.type('text/plain').send(textResponse);
  } catch (error) {
    handleError(res, error, 'text');
  }
});

/**
 * PUT /timezone/area - List timezones for specific area (JSON)
 * Body: { area: string }
 */
router.put('/timezone/area', (req, res) => {
  try {
    const { area } = req.body || {};
    const timezones = timezoneService.getTimezonesByArea(area);
    
    if (timezones.length === 0) {
      throw new Error(`Unknown area: ${area}`);
    }
    
    res.json(timezones);
  } catch (error) {
    handleError(res, error);
  }
});

/**
 * PUT /timezone/area.txt - List timezones for specific area (Plain text)
 * Body: { area: string }
 */
router.put('/timezone/area.txt', (req, res) => {
  try {
    const { area } = req.body || {};
    const timezones = timezoneService.getTimezonesByArea(area);
    
    if (timezones.length === 0) {
      throw new Error(`Unknown area: ${area}`);
    }
    
    const textResponse = timezoneService.formatTimezonesAsText(timezones);
    res.type('text/plain').send(textResponse);
  } catch (error) {
    handleError(res, error, 'text');
  }
});

/**
 * PUT /timezone/time - Get current time for timezone (JSON)
 * Body: { area: string, location: string, region?: string }
 */
router.put('/timezone/time', async (req, res) => {
  try {
    const { area, location, region } = req.body || {};
    const timezone = timezoneService.validateTimezoneParams(area, location, region);
    const clientIP = getClientIP(req);
    const timeData = await timezoneService.getTimeDataForTimezone(timezone, clientIP);
    
    res.json(timeData);
  } catch (error) {
    handleError(res, error);
  }
});

/**
 * PUT /timezone/time.txt - Get current time for timezone (Plain text)
 * Body: { area: string, location: string, region?: string }
 */
router.put('/timezone/time.txt', async (req, res) => {
  try {
    const { area, location, region } = req.body || {};
    const timezone = timezoneService.validateTimezoneParams(area, location, region);
    const clientIP = getClientIP(req);
    const timeData = await timezoneService.getTimeDataForTimezone(timezone, clientIP);
    const textResponse = timezoneService.formatAsText(timeData);
    
    res.type('text/plain').send(textResponse);
  } catch (error) {
    handleError(res, error, 'text');
  }
});

// Region-specific routes consolidated into /timezone/time and /timezone/time.txt via JSON body

/**
 * PUT /ip - Get current time based on client IP or specified IP (JSON)
 * Body: { ipv4?: string }
 */
router.put('/ip', async (req, res) => {
  try {
    const { ipv4 } = req.body || {};
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4 && !ipPattern.test(ipv4)) {
      throw new Error(`Invalid IPv4 address: ${ipv4}`);
    }
    const sourceIP = ipv4 && ipv4.trim() !== '' ? ipv4 : getClientIP(req);
    const timezone = timezoneService.getTimezoneForIP(sourceIP);
    const timeData = await timezoneService.getTimeDataForTimezone(timezone, sourceIP);
    
    res.json(timeData);
  } catch (error) {
    handleError(res, error);
  }
});

/**
 * PUT /ip.txt - Get current time based on client IP or specified IP (Plain text)
 * Body: { ipv4?: string }
 */
router.put('/ip.txt', async (req, res) => {
  try {
    const { ipv4 } = req.body || {};
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4 && !ipPattern.test(ipv4)) {
      throw new Error(`Invalid IPv4 address: ${ipv4}`);
    }
    const sourceIP = ipv4 && ipv4.trim() !== '' ? ipv4 : getClientIP(req);
    const timezone = timezoneService.getTimezoneForIP(sourceIP);
    const timeData = await timezoneService.getTimeDataForTimezone(timezone, sourceIP);
    const textResponse = timezoneService.formatAsText(timeData);
    
    res.type('text/plain').send(textResponse);
  } catch (error) {
    handleError(res, error, 'text');
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
