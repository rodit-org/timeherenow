// Copyright (c) 2024 Discernible, Inc. All rights reserved.
// NEAR RPC Timestamp Service for Time Here Now

const config = require('config');
const axios = require('axios');

/**
 * NEAR RPC Timestamp Service
 * Fetches timestamps from NEAR blockchain RPC instead of using system time
 */
class NearTimestampService {
  constructor() {
    // NEAR mainnet RPC endpoint
    this.rpcEndpoint = config.get('NEAR_RPC_URL');
    this.timeout = config.get('NEAR_RPC_TIMEOUT');
    
    // Cache timestamp for a short period to avoid excessive RPC calls
    this.cache = {
      timestamp: null,
      lastFetch: 0,
      ttl: 1000 // 1 second cache TTL
    };
  }

  /**
   * Get current timestamp from NEAR RPC
   * Returns timestamp in nanoseconds
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
        // NEAR returns timestamp in nanoseconds, but we need milliseconds for JS Date
        const nearTimestampNs = response.data.result.sync_info.latest_block_time;
        const nearTimestampMs = Math.floor(nearTimestampNs / 1_000_000);
        
        // Update cache
        this.cache.timestamp = nearTimestampMs;
        this.cache.lastFetch = now;
        
        return nearTimestampMs;
      } else {
        throw new Error('Invalid response format from NEAR RPC');
      }
    } catch (error) {
      console.error('Error fetching NEAR timestamp:', error.message);
      throw new Error(`Failed to fetch NEAR timestamp: ${error.message}`);
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

module.exports = NearTimestampService;
