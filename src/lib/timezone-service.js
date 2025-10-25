// Copyright (c) 2024 Discernible, Inc. All rights reserved.
  // Time Here Now - API Service

  const geoip = require('geoip-lite');
  const { getTimeZones } = require('@vvo/tzdb');
  const { blockchainService } = require('@rodit/rodit-auth-be');

/**
 * TimeZone Service for Time Here Now API
 * Provides timezone data, current time information, and IP-based timezone lookup
 * Uses NEAR RPC timestamp from @rodit/rodit-auth-be SDK
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
    
    // NEAR polling cache and settings
    this.nearCache = { ms: null, iso: null, fetchedAt: 0 };
    this._pollIntervalMs = parseInt(process.env.NEAR_POLL_MS) || 200; // 5 Hz
    this._blockIntervalMs = parseInt(process.env.NEAR_BLOCK_MS) || 500; // ~0.5s
    this._networkMarginMs = parseInt(process.env.NEAR_NET_MARGIN_MS) || 50;

    // Start background polling
    this._startNearPolling();
  }

  /**
   * Get current timestamp from NEAR RPC via SDK
   * Returns timestamp in milliseconds
   */
  async _getNearTimestamp() {
    // SDK returns nanosecond timestamp, convert to milliseconds
    const timestampNs = await blockchainService.nearorg_rpc_timestamp();
    return Math.floor(timestampNs / 1_000_000);
  }

  /**
   * Get current Date object using NEAR timestamp
   */
  async _getCurrentDate() {
    const cachedMs = this._getCachedNearMsOrThrow();
    return new Date(cachedMs);
  }

  /**
   * Health check for NEAR RPC connection via SDK
   */
  async healthCheck() {
    try {
      const timestampNs = await blockchainService.nearorg_rpc_timestamp();
      const ms = Math.floor(timestampNs / 1_000_000);
      const isoString = new Date(ms).toISOString();
      const rpcEndpoint = process.env.NEAR_RPC_ENDPOINT || 'https://rpc.mainnet.near.org';
      const now = Date.now();
      const cache = this.nearCache || {};
      const cacheAvailable = typeof cache.ms === 'number' && !Number.isNaN(cache.ms);
      const lastFetchTs = cache.fetchedAt ? new Date(cache.fetchedAt).toISOString() : null;
      const lastFetchAgeMs = cache.fetchedAt ? Math.max(0, now - cache.fetchedAt) : null;
      const lastBlockTs = cache.iso || null;
      const lastBlockAgeMs = cache.ms ? Math.max(0, now - cache.ms) : null;
      const likelyDiff = cache.ms ? this._likelyDiff99Ms(cache.ms) : null;
      return {
        status: 'healthy',
        endpoint: rpcEndpoint,
        timestamp: isoString,
        cache_available: !!cacheAvailable,
        last_fetch_timestamp: lastFetchTs,
        last_fetch_age_ms: lastFetchAgeMs,
        last_block_timestamp: lastBlockTs,
        last_block_age_ms: lastBlockAgeMs,
        poll_interval_ms: this._pollIntervalMs,
        block_interval_ms: this._blockIntervalMs,
        network_margin_ms: this._networkMarginMs,
        likely_time_difference_ms: likelyDiff
      };
    } catch (error) {
      const rpcEndpoint = process.env.NEAR_RPC_ENDPOINT || 'https://rpc.mainnet.near.org';
      return {
        status: 'unhealthy',
        endpoint: rpcEndpoint,
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Get current NEAR polling status and latest cached values
   */
  getNearStatus() {
    const now = Date.now();
    const cache = this.nearCache || {};
    const cacheAvailable = typeof cache.ms === 'number' && !Number.isNaN(cache.ms);
    if (!cacheAvailable) {
      throw new Error('NEAR time unavailable');
    }
    return {
      ms: cache.ms,
      iso: cache.iso,
      fetchedAt: cache.fetchedAt,
      last_fetch_timestamp: cache.fetchedAt ? new Date(cache.fetchedAt).toISOString() : null,
      last_fetch_age_ms: cache.fetchedAt ? Math.max(0, now - cache.fetchedAt) : null,
      last_block_timestamp: cache.iso || null,
      last_block_age_ms: cache.ms ? Math.max(0, now - cache.ms) : null,
      likely_time_difference_ms: this._likelyDiff99Ms(cache.ms),
      poll_interval_ms: this._pollIntervalMs,
      block_interval_ms: this._blockIntervalMs,
      network_margin_ms: this._networkMarginMs
    };
  }

  // Start polling NEAR time at configured frequency
  _startNearPolling() {
    if (this._pollTimer) return;
    const poll = async () => {
      try {
        const timestampNs = await blockchainService.nearorg_rpc_timestamp();
        // Convert nanosecond timestamp to milliseconds
        const ms = Math.floor(timestampNs / 1_000_000);
        const iso = new Date(ms).toISOString();
        this.nearCache = { ms, iso, fetchedAt: Date.now() };
      } catch (err) {
        // Keep last good value; do not update cache on failure
      }
    };
    // Prime immediately
    poll().catch(() => {});
    this._pollTimer = setInterval(poll, this._pollIntervalMs);
  }

  /**
   * Wait for NEAR cache to be initialized with first successful poll
   * Call this before starting the server to ensure cache is ready
   * @param {number} timeoutMs - Maximum time to wait (default 10000ms)
   * @returns {Promise<void>}
   */
  async waitForNearCache(timeoutMs = 10000) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      const cache = this.nearCache || {};
      if (typeof cache.ms === 'number' && !Number.isNaN(cache.ms)) {
        return; // Cache is ready
      }
      // Wait 100ms before checking again
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error(`NEAR cache initialization timeout after ${timeoutMs}ms`);
  }

  // Read cached NEAR ms or throw if unavailable
  _getCachedNearMsOrThrow() {
    const { ms } = this.nearCache || {};
    if (typeof ms !== 'number' || Number.isNaN(ms)) {
      throw new Error('NEAR time unavailable');
    }
    return ms;
  }

  // Conservative 99%-likely difference between real time and cached NEAR time (ms)
  _likelyDiff99Ms(cachedMs) {
    const now = Date.now();
    const observedLag = Math.max(0, now - cachedMs);
    const modelBound = this._blockIntervalMs + this._pollIntervalMs + this._networkMarginMs;
    return Math.max(observedLag, modelBound);
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

    // Use most recent cached NEAR time
    const nearDate = await this._getCurrentDate();
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
      week_number: week,
      likely_time_difference_ms: this._likelyDiff99Ms(utcMs)
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
