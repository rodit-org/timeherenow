// Copyright (c) 2024 Discernible, Inc. All rights reserved.
  // Time Here Now - API Service

  const geoip = require('geoip-lite');
  const axios = require('axios');
  const { getTimeZones } = require('@vvo/tzdb');

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
    // Cached lists
    this.allTimezonesCache = null;
    this.timezonesByAreaCache = null;

    // Cache CLDR data per locale
    this.cldrCache = {
      tzNamesByLocale: {}
    };

    // Initialize NEAR timestamp service
    this.nearTimestampService = new NearTimestampService();
  }

  // Helper: zero-pad
  _pad2(n) { return String(n).padStart(2, '0'); }

  // Helper: format offset minutes to "+HH:MM" or "-HH:MM"
  _formatOffset(minutes) {
    const sign = minutes >= 0 ? '+' : '-';
    const abs = Math.abs(minutes);
    const hh = this._pad2(Math.floor(abs / 60));
    const mm = this._pad2(abs % 60);
    return `${sign}${hh}:${mm}`;
  }

  // Helper: format ISO string for a given UTC ms and offset minutes
  _isoStringWithOffset(utcMs, offsetMin) {
    const d = new Date(utcMs + offsetMin * 60 * 1000);
    const yyyy = d.getUTCFullYear();
    const MM = this._pad2(d.getUTCMonth() + 1);
    const DD = this._pad2(d.getUTCDate());
    const hh = this._pad2(d.getUTCHours());
    const mm = this._pad2(d.getUTCMinutes());
    const ss = this._pad2(d.getUTCSeconds());
    const mmm = String(d.getUTCMilliseconds()).padStart(3, '0');
    const off = this._formatOffset(offsetMin);
    return `${yyyy}-${MM}-${DD}T${hh}:${mm}:${ss}.${mmm}${off}`;
  }

  // Helper: day of week (0=Sunday..6=Saturday) for local time based on UTC ms + offset
  _dayOfWeek(utcMs, offsetMin) {
    const d = new Date(utcMs + offsetMin * 60 * 1000);
    const jsDow = d.getUTCDay(); // 0=Sun..6=Sat
    // Convert to ISO 8601: Mon=1..Sun=7
    return jsDow === 0 ? 7 : jsDow;
  }

  // Helper: day of year for local time
  _dayOfYear(utcMs, offsetMin) {
    const d = new Date(utcMs + offsetMin * 60 * 1000);
    const start = Date.UTC(d.getUTCFullYear(), 0, 1);
    const today = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
    return Math.floor((today - start) / 86400000) + 1;
  }

  // Helper: ISO week number for local time
  _isoWeekNumber(utcMs, offsetMin) {
    const d = new Date(utcMs + offsetMin * 60 * 1000);
    // Thursday in current week decides the year.
    const tmp = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    tmp.setUTCDate(tmp.getUTCDate() + 3 - ((tmp.getUTCDay() + 6) % 7));
    // Week 1 is the week with January 4th in it
    const week1 = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 4));
    return 1 + Math.round(((tmp - week1) / 86400000 - 3 + ((week1.getUTCDay() + 6) % 7)) / 7);
  }

  // Resolve preferred locale: prefer explicit, then base language, else 'en'
  _resolveLocale(locale) {
    if (!locale || typeof locale !== 'string') return 'en';
    let tag = locale.replace('_', '-');
    // Take first in list like "en-US,en;q=0.9"
    if (tag.includes(',')) tag = tag.split(',')[0];
    tag = tag.split(';')[0].trim();
    if (tag.length === 0) return 'en';
    return tag;
  }

  // Load and cache CLDR timeZoneNames for locale with fallback to language and 'en'
  _getCldrTimeZoneNames(locale) {
    const loc = this._resolveLocale(locale);
    if (this.cldrCache.tzNamesByLocale[loc]) return this.cldrCache.tzNamesByLocale[loc];
    const tryLocales = [loc, loc.split('-')[0], 'en'];
    for (const l of tryLocales) {
      try {
        const data = require(`cldr-data/main/${l}/dates/timeZoneNames.json`);
        // cache and return
        this.cldrCache.tzNamesByLocale[loc] = data;
        return data;
      } catch (e) {
        // continue
      }
    }
    return null;
  }

  // Convert a time zone id like "America/Los_Angeles" to CLDR zone path keys
  _tzToCldrPathSegments(tz) {
    return tz.split('/').map(seg => seg.replace(/-/g, '_'));
  }

  // Extract exemplar city from CLDR for given tz and locale
  _getExemplarCity(tz, locale) {
    const cldr = this._getCldrTimeZoneNames(locale);
    if (!cldr) return null;
    const locKey = Object.keys(cldr.main)[0];
    const zone = (((cldr || {}).main || {})[locKey] || {}).dates?.timeZoneNames?.zone;
    if (!zone) return null;
    const segs = this._tzToCldrPathSegments(tz);
    let node = zone;
    for (const seg of segs) {
      if (node && Object.prototype.hasOwnProperty.call(node, seg)) {
        node = node[seg];
      } else {
        node = null;
        break;
      }
    }
    if (node && typeof node === 'object' && node.exemplarCity) {
      return node.exemplarCity;
    }
    return null;
  }

  // Get localized time zone names and localized datetime using Intl
  _getLocalizedTZDisplay(tz, locale, date) {
    const resolved = this._resolveLocale(locale);
    const baseOpts = { timeZone: tz, year: 'numeric', month: 'long', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' };
    let longName = null, shortName = null, localizedDate = null;
    try {
      const dtfLong = new Intl.DateTimeFormat(resolved, { ...baseOpts, timeZoneName: 'long' });
      const partsLong = dtfLong.formatToParts(date);
      longName = (partsLong.find(p => p.type === 'timeZoneName') || {}).value || null;
      localizedDate = dtfLong.format(date);
    } catch {}
    try {
      const dtfShort = new Intl.DateTimeFormat(resolved, { ...baseOpts, timeZoneName: 'short' });
      const partsShort = dtfShort.formatToParts(date);
      shortName = (partsShort.find(p => p.type === 'timeZoneName') || {}).value || null;
    } catch {}
    return { longName, shortName, localizedDate, locale: resolved };
  }

  /**
   * Get all available timezones
   */
  async getAllTimezones() {
    if (this.allTimezonesCache) return this.allTimezonesCache;
    const names = getTimeZones({ includeUtc: true }).map(z => z.name);
    // Cache a sorted copy for stable responses
    this.allTimezonesCache = names.slice().sort();
    return this.allTimezonesCache;
  }

  /**
   * Get all timezones for a specific area
   */
  async getTimezonesByArea(area) {
    const all = await this.getAllTimezones();
    return all.filter(tz => typeof tz === 'string' && tz.startsWith(`${area}/`));
  }

  /**
   * Get all timezones for a specific ISO 3166-1 alpha-2 country code
   */
  async getTimezonesByCountryCode(countryCode) {
    if (!countryCode || typeof countryCode !== 'string') return [];
    const cc = countryCode.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc)) return [];
    const zones = getTimeZones({ includeUtc: true })
      .filter(z => z.countryCode === cc)
      .map(z => z.name);
    return Array.from(new Set(zones)).sort();
  }

  /**
   * Get all areas (top-level timezone categories)
   */
  async getAllAreas() {
    if (this.timezonesByAreaCache) return Object.keys(this.timezonesByAreaCache);
    const all = await this.getAllTimezones();
    const grouped = {};
    all.forEach(tz => {
      const parts = tz.split('/');
      if (parts.length >= 2) {
        const area = parts[0];
        if (!grouped[area]) grouped[area] = [];
        grouped[area].push(tz);
      }
    });
    this.timezonesByAreaCache = grouped;
    return Object.keys(grouped);
  }

  /**
   * Find timezone by area and location
   */
  async findTimezone(area, location, region = null) {
    let searchTimezone;
    if (region) {
      searchTimezone = `${area}/${location}/${region}`;
    } else {
      searchTimezone = `${area}/${location}`;
    }
    const all = await this.getAllTimezones();
    return all.includes(searchTimezone) ? searchTimezone : null;
  }

  /**
   * Get current time data for a timezone using NEAR RPC timestamp
   */
  async getTimeDataForTimezone(timezone, clientIp = null, locale = null) {
    const all = await this.getAllTimezones();
    if (!all.includes(timezone)) {
      throw new Error(`Invalid timezone: ${timezone}`);
    }

    // Get current time from NEAR RPC
    const nearDate = await this.nearTimestampService.getCurrentDate();
    const utcMs = nearDate.getTime();

    // Load tzdb and get info (includeUtc so UTC is always resolvable)
    const tzList = getTimeZones({ includeUtc: true });
    const tzInfo = tzList.find(z => z.name === timezone);
    if (!tzInfo) {
      throw new Error(`Unknown timezone: ${timezone}`);
    }

    const rawOffsetMin = tzInfo.rawOffsetInMinutes;
    const currentOffsetMin = tzInfo.currentTimeOffsetInMinutes;
    const isDst = currentOffsetMin !== rawOffsetMin;
    const dstOffsetMin = currentOffsetMin - rawOffsetMin;

    const localIso = this._isoStringWithOffset(utcMs, currentOffsetMin);
    const utcIso = new Date(utcMs).toISOString();
    const dow = this._dayOfWeek(utcMs, currentOffsetMin);
    const doy = this._dayOfYear(utcMs, currentOffsetMin);
    const week = this._isoWeekNumber(utcMs, currentOffsetMin);

    // Standards-only: compute resolved locale only
    const resolvedLocale = this._resolveLocale(locale);

    return {
      user_ip: clientIp || '::',
      date_time: localIso,
      day_of_week: dow,
      day_of_year: doy,
      dst_trueorfalse: isDst,
      dst_offset: dstOffsetMin * 60, // seconds
      raw_offset: rawOffsetMin * 60, // seconds
      time_zone: timezone,
      locale: resolvedLocale,
      unix_time: Math.floor(utcMs / 1000),
      utc_datetime: utcIso,
      utc_offset: this._formatOffset(currentOffsetMin),
      week_number: week
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
   * Validate timezone path parameters
   */
  async validateTimezoneParams(area, location, region = null) {
    if (!area) {
      throw new Error('Area parameter is required');
    }
    if (!location) {
      throw new Error('Location parameter is required');
    }
    const timezone = await this.findTimezone(area, location, region);
    if (!timezone) {
      const attempted = region ? `${area}/${location}/${region}` : `${area}/${location}`;
      throw new Error(`Unknown timezone: ${attempted}`);
    }
    return timezone;
  }
}

module.exports = TimeZoneService;
