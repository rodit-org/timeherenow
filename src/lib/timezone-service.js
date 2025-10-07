// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// Time Here Now - API Service

const moment = require('moment-timezone');
const geoip = require('geoip-lite');
const axios = require('axios');

/**
 * NEAR RPC Timestamp Service (inlined)
 * Fetches timestamps from NEAR blockchain RPC instead of using system time
 */
class NearTimestampService {
  constructor() {
    // NEAR mainnet RPC endpoint
    this.rpcEndpoint = process.env.NEAR_RPC_ENDPOINT || 'https://rpc.mainnet.near.org';
    this.timeout = parseInt(process.env.NEAR_RPC_TIMEOUT) || 5000; // 5 second timeout
    this.fallbackToSystemTime = process.env.NEAR_FALLBACK_SYSTEM_TIME !== 'false';

    // Cache timestamp for a short period to avoid excessive RPC calls
    this.cache = {
      timestamp: null,
      lastFetch: 0,
      ttl: 1000 // 1 second cache TTL
    };
  }

  /**
   * Get current timestamp from NEAR RPC
   * Returns timestamp in milliseconds
   */
  async getNearTimestamp() {
    try {
      // Check cache first
      const now = Date.now();
      if (this.cache.timestamp && (now - this.cache.lastFetch) < this.cache.ttl) {
        return this.cache.timestamp;
      }

      const response = await axios.post(this.rpcEndpoint, {
        jsonrpc: '2.0',
        id: 'dontcare',
        method: 'status',
        params: []
      }, {
        timeout: this.timeout,
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.data && response.data.result && response.data.result.sync_info) {
        // NEAR returns timestamp (implementation dependent). We normalize to ms when numeric.
        const nearTimestampNs = response.data.result.sync_info.latest_block_time;
        // If it's a number in ns, convert to ms; otherwise, fall back to Date.now()
        const nearTimestampMs = typeof nearTimestampNs === 'number'
          ? Math.floor(nearTimestampNs / 1_000_000)
          : Date.now();

        // Update cache
        this.cache.timestamp = nearTimestampMs;
        this.cache.lastFetch = now;

        return nearTimestampMs;
      } else {
        throw new Error('Invalid response format from NEAR RPC');
      }
    } catch (error) {
      console.error('Error fetching NEAR timestamp:', error.message);

      if (this.fallbackToSystemTime) {
        console.warn('Falling back to system time');
        return Date.now();
      } else {
        throw new Error(`Failed to fetch NEAR timestamp: ${error.message}`);
      }
    }
  }

  /**
   * Get current timestamp in seconds (Unix timestamp)
   */
  async getCurrentUnixTime() {
    const timestampMs = await this.getNearTimestamp();
    return Math.floor(timestampMs / 1000);
  }

  /**
   * Get current Date object using NEAR timestamp
   */
  async getCurrentDate() {
    const timestampMs = await this.getNearTimestamp();
    return new Date(timestampMs);
  }

  /**
   * Get current timestamp in ISO string format
   */
  async getCurrentISOString() {
    const date = await this.getCurrentDate();
    return date.toISOString();
  }

  /**
   * Health check for NEAR RPC connection
   */
  async healthCheck() {
    try {
      await this.getNearTimestamp();
      return {
        status: 'healthy',
        endpoint: this.rpcEndpoint,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        endpoint: this.rpcEndpoint,
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}

/**
 * TimeZone Service for Time Here Now API
 * Provides timezone data, current time information, and IP-based timezone lookup
 * Uses NEAR RPC timestamp instead of system time
 */
class TimeZoneService {
  constructor() {
    // Get all timezone names from moment-timezone
    this.allTimezones = moment.tz.names();
    
    // Group timezones by area for efficient lookup
    this.timezonesByArea = this.groupTimezonesByArea();
    
    // Initialize NEAR timestamp service
    this.nearTimestampService = new NearTimestampService();
  }

  /**
   * Group timezones by area (e.g., America, Europe, Asia)
   */
  groupTimezonesByArea() {
    const grouped = {};
    this.allTimezones.forEach(timezone => {
      const parts = timezone.split('/');
      if (parts.length >= 2) {
        const area = parts[0];
        if (!grouped[area]) {
          grouped[area] = [];
        }
        grouped[area].push(timezone);
      }
    });
    return grouped;
  }

  /**
   * Get all available timezones
   */
  getAllTimezones() {
    return this.allTimezones;
  }

  /**
   * Get all timezones for a specific area
   */
  getTimezonesByArea(area) {
    return this.timezonesByArea[area] || [];
  }

  /**
   * Get all areas (top-level timezone categories)
   */
  getAllAreas() {
    return Object.keys(this.timezonesByArea);
  }

  /**
   * Find timezone by area and location
   */
  findTimezone(area, location, region = null) {
    let searchTimezone;
    if (region) {
      searchTimezone = `${area}/${location}/${region}`;
    } else {
      searchTimezone = `${area}/${location}`;
    }
    
    return this.allTimezones.includes(searchTimezone) ? searchTimezone : null;
  }

  /**
   * Get current time data for a timezone using NEAR RPC timestamp
   */
  async getTimeDataForTimezone(timezone, clientIp = null) {
    if (!this.allTimezones.includes(timezone)) {
      throw new Error(`Invalid timezone: ${timezone}`);
    }

    // Get current time from NEAR RPC
    const nearTimestamp = await this.nearTimestampService.getCurrentDate();
    const now = moment(nearTimestamp).tz(timezone);
    const utcNow = moment(nearTimestamp).utc();
    
    // Get timezone info
    const zone = moment.tz.zone(timezone);
    const offset = now.utcOffset();
    const isDst = now.isDST();
    
    // Calculate DST information
    let dstFrom = null;
    let dstUntil = null;
    let rawOffset = offset;
    let dstOffset = 0;

    if (zone && zone.untils && zone.offsets) {
      // Find current period in timezone data
      const currentTime = now.valueOf();
      let periodIndex = -1;
      
      for (let i = 0; i < zone.untils.length; i++) {
        if (currentTime < zone.untils[i] || zone.untils[i] === Infinity) {
          periodIndex = i;
          break;
        }
      }
      
      if (periodIndex >= 0) {
        rawOffset = -zone.offsets[periodIndex];
        if (isDst) {
          dstOffset = offset - rawOffset;
          
          // Find DST transitions
          const currentYear = now.year();
          const yearStart = moment.tz(`${currentYear}-01-01`, timezone).valueOf();
          const yearEnd = moment.tz(`${currentYear + 1}-01-01`, timezone).valueOf();
          
          for (let i = 0; i < zone.untils.length - 1; i++) {
            const transitionTime = zone.untils[i];
            if (transitionTime >= yearStart && transitionTime < yearEnd) {
              const beforeDst = -zone.offsets[i] !== rawOffset;
              const afterDst = -zone.offsets[i + 1] !== rawOffset;
              
              if (!beforeDst && afterDst) {
                // Start of DST
                dstFrom = moment(transitionTime).tz(timezone).format();
              } else if (beforeDst && !afterDst) {
                // End of DST
                dstUntil = moment(transitionTime).tz(timezone).format();
              }
            }
          }
        }
      }
    }

    return {
      abbreviation: now.format('z'),
      client_ip: clientIp || '0.0.0.0',
      datetime: now.format(),
      day_of_week: now.day(),
      day_of_year: now.dayOfYear(),
      dst: isDst,
      dst_from: dstFrom,
      dst_offset: dstOffset * 60, // Convert to seconds
      dst_until: dstUntil,
      raw_offset: rawOffset * 60, // Convert to seconds
      timezone: timezone,
      unixtime: now.unix(),
      utc_datetime: utcNow.format(),
      utc_offset: now.format('Z'),
      week_number: now.week()
    };
  }

  /**
   * Get timezone for IP address
   */
  getTimezoneForIP(ip) {
    const geo = geoip.lookup(ip);
    if (!geo || !geo.timezone) {
      // Default to UTC if no timezone found
      return 'UTC';
    }
    return geo.timezone;
  }

  /**
   * Format time data as plain text
   */
  formatAsText(timeData) {
    const lines = [];
    Object.entries(timeData).forEach(([key, value]) => {
      if (value !== null && value !== undefined) {
        lines.push(`${key}: ${value}`);
      }
    });
    return lines.join('\n');
  }

  /**
   * Format timezone list as plain text
   */
  formatTimezonesAsText(timezones) {
    return timezones.join('\n');
  }

  /**
   * Validate timezone path parameters
   */
  validateTimezoneParams(area, location, region = null) {
    if (!area) {
      throw new Error('Area parameter is required');
    }
    
    if (!location) {
      throw new Error('Location parameter is required');
    }
    
    const timezone = this.findTimezone(area, location, region);
    if (!timezone) {
      const attempted = region ? `${area}/${location}/${region}` : `${area}/${location}`;
      throw new Error(`Unknown timezone: ${attempted}`);
    }
    
    return timezone;
  }
}

module.exports = TimeZoneService;
