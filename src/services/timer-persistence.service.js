const fs = require('fs').promises;
const path = require('path');
const { logger } = require('@rodit/rodit-auth-be');

/**
 * Timer Persistence Manager
 * 
 * Handles saving and restoring active timers to/from disk to survive server restarts.
 * 
 * Design decisions:
 * - Timers are saved hourly to minimize data loss during unexpected restarts
 * - Only timer metadata is saved (not setTimeout handles, which can't be serialized)
 * - On restore, timers are rescheduled based on their original execute_at time
 * - Timers that should have already fired are skipped (never fire late)
 * - File writes are atomic using temp file + rename to prevent corruption
 * 
 * Maximum timer duration: 48 hours (172800 seconds)
 * Rationale: Balances flexibility with resource management. With hourly persistence,
 * the maximum data loss window is 1 hour, making 48-hour timers practical.
 */

class TimerPersistence {
  constructor(persistencePath = null) {
    // Default to data directory in project root
    this.persistencePath = persistencePath || path.join(process.cwd(), 'data', 'timers.json');
    this.autoSaveInterval = null;
    this.autoSaveIntervalMs = 60 * 60 * 1000; // 1 hour
  }

  /**
   * Serialize timer store to JSON-compatible format
   * Excludes setTimeout handles which cannot be serialized
   */
  serializeTimers(timerStore) {
    const serialized = [];
    
    for (const [sessionKey, sessionMap] of timerStore.entries()) {
      for (const [timerId, event] of sessionMap.entries()) {
        serialized.push({
          timer_id: event.timer_id,
          session_key: event.session_key,
          user_id: event.user_id,
          scheduled_at: event.scheduled_at,
          execute_at: event.execute_at,
          delay_seconds: event.delay_seconds,
          payload: event.payload
        });
      }
    }
    
    return serialized;
  }

  /**
   * Save active timers to disk atomically
   * Uses temp file + rename to prevent corruption
   */
  async saveTimers(timerStore) {
    try {
      const serialized = this.serializeTimers(timerStore);
      const data = JSON.stringify({
        version: 1,
        saved_at: new Date().toISOString(),
        timer_count: serialized.length,
        timers: serialized
      }, null, 2);

      // Ensure directory exists
      const dir = path.dirname(this.persistencePath);
      await fs.mkdir(dir, { recursive: true });

      // Atomic write: temp file + rename
      const tempPath = `${this.persistencePath}.tmp`;
      await fs.writeFile(tempPath, data, 'utf8');
      await fs.rename(tempPath, this.persistencePath);

      logger.infoWithContext('Timers saved to disk', {
        component: 'TimerPersistence',
        path: this.persistencePath,
        count: serialized.length
      });

      return { success: true, count: serialized.length };
    } catch (error) {
      logger.errorWithContext('Failed to save timers', {
        component: 'TimerPersistence',
        path: this.persistencePath,
        error: error.message
      }, error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Load timers from disk
   * Returns array of timer objects or empty array if file doesn't exist
   */
  async loadTimers() {
    try {
      const data = await fs.readFile(this.persistencePath, 'utf8');
      const parsed = JSON.parse(data);

      logger.infoWithContext('Timers loaded from disk', {
        component: 'TimerPersistence',
        path: this.persistencePath,
        count: parsed.timer_count,
        saved_at: parsed.saved_at
      });

      return parsed.timers || [];
    } catch (error) {
      if (error.code === 'ENOENT') {
        logger.infoWithContext('No timer persistence file found (first run)', {
          component: 'TimerPersistence',
          path: this.persistencePath
        });
        return [];
      }

      logger.errorWithContext('Failed to load timers', {
        component: 'TimerPersistence',
        path: this.persistencePath,
        error: error.message
      }, error);
      return [];
    }
  }

  /**
   * Start automatic hourly saves
   */
  startAutoSave(timerStore) {
    if (this.autoSaveInterval) {
      logger.warnWithContext('Auto-save already running', {
        component: 'TimerPersistence'
      });
      return;
    }

    this.autoSaveInterval = setInterval(() => {
      this.saveTimers(timerStore);
    }, this.autoSaveIntervalMs);

    logger.infoWithContext('Timer auto-save started', {
      component: 'TimerPersistence',
      intervalMs: this.autoSaveIntervalMs,
      path: this.persistencePath
    });
  }

  /**
   * Stop automatic saves and perform final save
   */
  async stopAutoSave(timerStore) {
    if (this.autoSaveInterval) {
      clearInterval(this.autoSaveInterval);
      this.autoSaveInterval = null;
      
      // Final save before shutdown
      await this.saveTimers(timerStore);
      
      logger.infoWithContext('Timer auto-save stopped', {
        component: 'TimerPersistence'
      });
    }
  }
}

module.exports = TimerPersistence;
