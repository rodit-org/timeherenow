/**
 * Performance monitoring service for tracing and metrics collection
 * Copyright (c) 2025 Discernible, Inc. All rights reserved.
 */

const { ulid } = require('ulid');
const logger = require('./logger');
const config = require('./configsdk');
const os = require('os');

// Load level constants from configuration
const LOAD_LEVELS = config.get('PERFORMANCE.LOAD_LEVELS');

// Load thresholds (requests per minute) from configuration
const LOAD_THRESHOLDS = config.get('PERFORMANCE.LOAD_THRESHOLDS');

class PerformanceService {
  constructor() {
    this.traces = new Map();
    this.metrics = {
      requestCount: 0,
      errorCount: 0,
      totalDuration: 0,
      maxDuration: 0,
      minDuration: Number.MAX_SAFE_INTEGER,
      blockchainCalls: 0,
      blockchainDuration: 0,
      authenticationCalls: 0,
      authenticationDuration: 0
    };
    this.currentLoadLevel = LOAD_LEVELS.LOW;
    this.requestsPerMinute = 0;
    this.lastMinuteTimestamp = Date.now();
    this.requestsThisMinute = 0;
  }

  /**
   * Initialize the performance monitoring service
   * 
   */
  initialize() {
    logger.info('Performance monitoring service initialized', {
      component: 'PerformanceService',
      method: 'initialize'
    });

    // Start monitoring health load
    this._startLoadMonitoring();

    return this;
  }

  /**
   * Start monitoring health load
   * 
   * @private
   */
  _startLoadMonitoring() {
    // Update load level every minute
    setInterval(() => this._updateLoadLevel(), 60000);

    logger.info('Load monitoring started', {
      component: 'PerformanceService',
      method: '_startLoadMonitoring',
      initialLoadLevel: this.currentLoadLevel
    });
  }

  /**
   * Update the current load level based on recent request rate
   * 
   * @private
   */
  _updateLoadLevel() {
    const now = Date.now();
    const elapsedMs = now - this.lastMinuteTimestamp;
    
    if (elapsedMs >= 60000) {
      // Calculate requests per minute
      this.requestsPerMinute = Math.round(this.requestsThisMinute * (60000 / elapsedMs));
      
      // Determine load level based on request rate
      let newLoadLevel;
      if (this.requestsPerMinute > LOAD_THRESHOLDS.CRITICAL) {
        newLoadLevel = LOAD_LEVELS.CRITICAL;
      } else if (this.requestsPerMinute > LOAD_THRESHOLDS.HIGH) {
        newLoadLevel = LOAD_LEVELS.HIGH;
      } else if (this.requestsPerMinute > LOAD_THRESHOLDS.MEDIUM) {
        newLoadLevel = LOAD_LEVELS.MEDIUM;
      } else {
        newLoadLevel = LOAD_LEVELS.LOW;
      }
      
      // Log if load level changed
      if (newLoadLevel !== this.currentLoadLevel) {
        logger.info('System load level changed', {
          component: 'PerformanceService',
          method: '_updateLoadLevel',
          previousLevel: this.currentLoadLevel,
          newLevel: newLoadLevel,
          requestsPerMinute: this.requestsPerMinute
        });
      }
      
      // Update state
      this.currentLoadLevel = newLoadLevel;
      this.lastMinuteTimestamp = now;
      this.requestsThisMinute = 0;
    }
  }

  /**
   * Record a new request for load monitoring
   * 
   * @param {Object} req - Express request object
   */
  recordRequest(req) {
    // Increment request counter for load monitoring
    this.requestsThisMinute++;
    
    // Update total request count metric
    this.metrics.requestCount++;
    
    // Only log in verbose mode to avoid excessive logging during high load
    if (this.shouldUseVerboseLogging()) {
      logger.debug('Request recorded for load monitoring', {
        component: 'PerformanceService',
        method: 'recordRequest',
        path: req.path,
        requestMethod: req.method,
        requestsThisMinute: this.requestsThisMinute,
        currentLoadLevel: this.currentLoadLevel
      });
    }
  }

  /**
   * Record a metric
   * Uses the standardized logger.metric method for consistent metric collection
   * while also updating internal state for load monitoring
   * 
   * @param {string} metricName - Name of the metric
   * @param {number} value - Value to record
   * @param {Object} tags - Additional tags for the metric
   */
  recordMetric(metricName, value, tags = {}) {
    // Always use the standardized logger.metric method for metrics
    logger.metric(metricName, value, {
      ...tags,
      component: 'PerformanceService',
      load_level: this.currentLoadLevel
    });
    
    // Update internal metrics for load monitoring and reporting
    switch(metricName) {
      case 'request_count':
      case 'http_request_duration_ms':
        this.metrics.requestCount += (metricName === 'request_count' ? value : 1);
        // Also update the request counter for load monitoring
        this.requestsThisMinute++;
        break;
      case 'error_count':
      case 'http_errors_total':
        this.metrics.errorCount += value;
        break;
      case 'authentication_duration':
      case 'authentication_duration_ms':
        this.metrics.authenticationCalls++;
        this.metrics.authenticationDuration += value;
        break;
      case 'blockchain_duration':
      case 'blockchain_duration_ms':
        this.metrics.blockchainCalls++;
        this.metrics.blockchainDuration += value;
        break;
      case 'authentication_error':
      case 'blockchain_error':
        this.metrics.errorCount += value;
        break;
    }
  }

  /**
   * Start a trace for performance monitoring
   * 
   * @param {string} operationName - Name of the operation being traced
   * @param {Object} metadata - Additional metadata for the trace
   * @returns {string} Trace ID
   */
  startTrace(operationName, metadata = {}) {
    const traceId = metadata.traceId || ulid();
    const startTime = Date.now();
    
    this.traces.set(traceId, {
      id: traceId,
      operation: operationName,
      startTime,
      metadata,
      spans: [],
      completed: false
    });
    
    // Log trace start as a metric
    logger.metric('trace_started_total', 1, {
      operation: operationName,
      component: 'PerformanceService',
      request_id: metadata.requestId
    });
    
    if (this.shouldUseVerboseLogging()) {
      logger.debug(`Started trace for ${operationName}`, {
        component: 'PerformanceService',
        method: 'startTrace',
        traceId,
        operation: operationName,
        metadata: JSON.stringify(metadata)
      });
    }
    
    return traceId;
  }

  /**
   * Add a span to an existing trace
   * 
   * @param {string} traceId - ID of the parent trace
   * @param {string} spanName - Name of the span
   * @param {Object} metadata - Additional metadata for the span
   * @returns {Object} Span object with stop function
   */
  startSpan(traceId, spanName, metadata = {}) {
    const trace = this.traces.get(traceId);
    
    if (!trace) {
      logger.warn('Attempted to add span to non-existent trace', {
        component: 'PerformanceService',
        method: 'startSpan',
        traceId,
        spanName
      });
      
      return {
        id: ulid(),
        stop: () => {}
      };
    }
    
    const spanId = ulid();
    const span = {
      id: spanId,
      name: spanName,
      startTime: Date.now(),
      metadata: { ...metadata },
      parentId: traceId
    };
    
    trace.spans.push(span);
    
    // Only log in low load conditions
    if (this.currentLoadLevel === LOAD_LEVELS.LOW) {
      logger.debug('Span started', {
        component: 'PerformanceService',
        method: 'startSpan',
        traceId,
        spanId,
        spanName
      });
    }
    
    return {
      id: spanId,
      stop: () => this.stopSpan(traceId, spanId)
    };
  }

  /**
   * Stop a span and record its duration
   * 
   * @param {string} traceId - ID of the parent trace
   * @param {string} spanId - ID of the span to stop
   */
  stopSpan(traceId, spanId) {
    const trace = this.traces.get(traceId);
    
    if (!trace) {
      return;
    }
    
    const span = trace.spans.find(s => s.id === spanId);
    
    if (!span) {
      return;
    }
    
    span.endTime = Date.now();
    span.duration = span.endTime - span.startTime;
    
    // Track specific metrics based on span class
    if (span.name.includes('blockchain')) {
      this.metrics.blockchainCalls++;
      this.metrics.blockchainDuration += span.duration;
    } else if (span.name.includes('auth')) {
      this.metrics.authenticationCalls++;
      this.metrics.authenticationDuration += span.duration;
    }
    
    // Only log in low load conditions
    if (this.currentLoadLevel === LOAD_LEVELS.LOW) {
      const logLevel = this._getDurationLogLevel(span.duration);
      
      logger[logLevel]('Span completed', {
        component: 'PerformanceService',
        method: 'stopSpan',
        traceId,
        spanId,
        spanName: span.name,
        duration: span.duration
      });
    }
  }

  /**
   * Complete a trace with results
   * 
   * @param {string} traceId - ID of the trace to complete
   * @param {Object} results - Results of the operation
   * @returns {boolean} Whether the trace was successfully completed
   */
  completeTrace(traceId, results = {}) {
    if (!this.traces.has(traceId)) {
      logger.warn(`Attempted to complete unknown trace: ${traceId}`, {
        component: 'PerformanceService',
        method: 'completeTrace'
      });
      return false;
    }
    
    const trace = this.traces.get(traceId);
    if (trace.completed) {
      logger.warn(`Attempted to complete already completed trace: ${traceId}`, {
        component: 'PerformanceService',
        method: 'completeTrace'
      });
      return false;
    }
    
    const endTime = Date.now();
    const duration = endTime - trace.startTime;
    
    // Update the trace with completion info
    trace.completed = true;
    trace.endTime = endTime;
    trace.duration = duration;
    trace.results = results;
    
    // Log trace completion as a metric
    logger.metric('trace_duration_ms', duration, {
      operation: trace.operation,
      component: 'PerformanceService',
      status: results.success !== false ? 'success' : 'failure',
      error: results.error ? 'true' : 'false',
      status_code: results.statusCode || 0
    });
    
    // If there was an error, log an error metric
    if (results.error) {
      logger.metric('trace_errors_total', 1, {
        operation: trace.operation,
        component: 'PerformanceService',
        error_type: typeof results.error === 'string' ? results.error : 'unknown'
      });
    }
    
    if (this.shouldUseVerboseLogging() || results.error) {
      logger.debug(`Completed trace for ${trace.operation}`, {
        component: 'PerformanceService',
        method: 'completeTrace',
        traceId,
        operation: trace.operation,
        duration,
        success: results.success !== false,
        error: results.error,
        metadata: trace.metadata ? JSON.stringify(trace.metadata) : null
      });
    }
    
    return true;
  }

  /**
   * End a trace (alias for completeTrace)
   * 
   * @param {string} traceId - ID of the trace to end
   * @param {Object} result - Result of the operation
   * @returns {Object} Completed trace with metrics
   */
  endTrace(traceId, result = {}) {
    return this.completeTrace(traceId, result);
  }

  /**
   * Get a trace by ID
   * 
   * @param {string} traceId - ID of the trace to retrieve
   * @returns {Object} Trace object
   */
  getTrace(traceId) {
    return this.traces.get(traceId);
  }

  /**
   * Get current performance metrics
   * 
   * @returns {Object} Current metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      currentLoadLevel: this.currentLoadLevel,
      requestsPerMinute: this.requestsPerMinute
    };
  }

  /**
   * Reset performance metrics
   */
  resetMetrics() {
    this.metrics = {
      requestCount: 0,
      errorCount: 0,
      totalDuration: 0,
      maxDuration: 0,
      minDuration: Number.MAX_SAFE_INTEGER,
      blockchainCalls: 0,
      blockchainDuration: 0,
      authenticationCalls: 0,
      authenticationDuration: 0
    };
    
    logger.info('Performance metrics reset', {
      component: 'PerformanceService',
      method: 'resetMetrics'
    });
  }

  /**
   * Get appropriate log level based on duration
   * @private
   * 
   * @param {number} duration - Operation duration in ms
   * @returns {string} Log level to use
   */
  _getDurationLogLevel(duration) {
    if (duration > 1000) {
      return 'warn'; // Over 1 second
    } else if (duration > 500) {
      return 'info'; // 500ms - 1 second
    } else {
      return 'debug'; // Under 500ms
    }
  }

  /**
   * Check if verbose logging should be used based on current load
   * 
   * @returns {boolean} Whether to use verbose logging
   */
  shouldUseVerboseLogging() {
    // Only use verbose logging in low and medium load conditions
    return this.currentLoadLevel === LOAD_LEVELS.LOW || 
           this.currentLoadLevel === LOAD_LEVELS.MEDIUM;
  }

  /**
   * Get health resource usage metrics
   * 
   * @returns {Object} System resource metrics
   */
  getSystemMetrics() {
    const cpuUsage = process.cpuUsage();
    const memoryUsage = process.memoryUsage();
    
    return {
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system,
        loadAvg: os.loadavg()
      },
      memory: {
        rss: memoryUsage.rss,
        heapTotal: memoryUsage.heapTotal,
        heapUsed: memoryUsage.heapUsed,
        external: memoryUsage.external,
        arrayBuffers: memoryUsage.arrayBuffers
      },
      uptime: process.uptime(),
      timestamp: Date.now()
    };
  }
}

// Create and export singleton instance
const performanceService = new PerformanceService();
// Initialize the service
performanceService.initialize();
module.exports = performanceService;
