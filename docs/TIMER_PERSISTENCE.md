# Timer Persistence

## Overview

The Time Here Now API supports scheduling delayed webhooks with a maximum delay of **48 hours (172800 seconds)**. To ensure timers survive server restarts, pod replacements, or API reboots, the system implements automatic timer persistence.

## How It Works

### Automatic Hourly Saves

- Active timers are automatically saved to disk **every hour**
- Saves are atomic (using temp file + rename) to prevent corruption
- Default storage location: `data/timers.json` in the project root

### Restoration on Startup

When the server starts:
1. Loads saved timers from disk
2. Calculates remaining time for each timer
3. **Skips expired timers** (never fires late)
4. Reschedules active timers with adjusted delays

### Graceful Shutdown

On `SIGTERM` or `SIGINT`:
1. Stops the hourly auto-save interval
2. Performs a final save of all active timers
3. Exits cleanly

## Data Loss Window

**Maximum data loss: 1 hour**

If the server crashes unexpectedly between auto-saves, timers scheduled during that hour may be lost. However:
- Timers scheduled before the last save will be restored
- The hourly save interval minimizes this risk
- Graceful shutdowns (deployments, restarts) trigger immediate saves

## Design Decisions

### Why 48 Hours?

The previous 24-hour limit was increased to 48 hours because:
- **Persistence reduces risk**: With hourly saves, longer timers are practical
- **Flexibility**: Users can schedule timers for the next day or two
- **Resource balance**: Still prevents abuse while supporting real use cases

### Why Never Fire Late?

Timers that should have already fired are **intentionally skipped** on restore because:
- **Correctness**: Webhooks should fire at the scheduled time, not arbitrarily later
- **Predictability**: Users can rely on timers either firing on time or not at all
- **Idempotency**: Prevents duplicate/late webhooks from confusing downstream systems

### Why Hourly Saves?

The 1-hour interval balances:
- **I/O overhead**: Frequent saves would impact performance
- **Data loss risk**: Hourly saves limit exposure to 1 hour of data
- **Disk usage**: Reasonable file write frequency

## File Format

```json
{
  "version": 1,
  "saved_at": "2025-10-24T14:35:00.000Z",
  "timer_count": 3,
  "timers": [
    {
      "timer_id": "01JBEXAMPLE123",
      "session_key": "user-session-key",
      "user_id": "user123",
      "scheduled_at": "2025-10-24T14:00:00.000Z",
      "execute_at": "2025-10-24T16:00:00.000Z",
      "delay_seconds": 7200,
      "payload": { "custom": "data" }
    }
  ]
}
```

## Configuration

### Custom Storage Path

```javascript
const TimerPersistence = require('./lib/timer-persistence');
const persistence = new TimerPersistence('/custom/path/timers.json');
```

### Change Auto-Save Interval

Modify `autoSaveIntervalMs` in `src/lib/timer-persistence.js`:

```javascript
this.autoSaveIntervalMs = 30 * 60 * 1000; // 30 minutes instead of 1 hour
```

## Monitoring

### Logs

The system logs key events:

```
Timer persistence initialized
Timers saved to disk (count: 5)
Timers loaded from disk (count: 5, saved_at: ...)
Timer restoration complete (total: 5, restored: 4, skipped: 1)
Skipping expired timer (timer_id: ..., expired_by_ms: 3600000)
```

### Metrics

Timer callbacks include a `restored: true` flag in metrics when fired from restored timers.

## Operational Considerations

### Kubernetes/Docker Deployments

- Mount a persistent volume at `/app/data` to preserve timers across pod restarts
- Use `terminationGracePeriodSeconds: 30` to allow graceful shutdown saves
- Consider using a shared volume for multi-replica deployments (though timers are session-specific)

### Backup Strategy

The `data/timers.json` file can be backed up as part of regular backups. However:
- Timers are ephemeral by nature (max 48 hours)
- Restoring old backups may result in many skipped timers
- Focus on preventing data loss rather than long-term archival

### Scaling Considerations

Current implementation uses in-memory storage with disk persistence:
- **Single instance**: Works perfectly
- **Multiple instances**: Each instance maintains its own timer store
- **Load balancer**: Session affinity ensures users hit the same instance

For true multi-instance support, consider:
- Shared Redis/database for timer storage
- Distributed job queue (BullMQ, AWS SQS)
- Leader election for timer management

## Testing

To verify persistence works:

1. Schedule a timer with a long delay:
   ```bash
   curl -X POST http://localhost:3000/api/timers/schedule \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"delay_seconds": 3600, "payload": {"test": true}}'
   ```

2. Check the persistence file:
   ```bash
   cat data/timers.json
   ```

3. Restart the server:
   ```bash
   # Send SIGTERM for graceful shutdown
   kill -TERM $(pgrep -f "node.*app.js")
   npm start
   ```

4. Verify timer was restored in logs:
   ```
   Timer restoration complete (total: 1, restored: 1, skipped: 0)
   ```

## Troubleshooting

### Timers Not Restoring

- Check file permissions on `data/` directory
- Verify `data/timers.json` exists and is valid JSON
- Check logs for "Failed to load timers" errors

### All Timers Skipped on Restore

- Server was down longer than timer delays
- This is expected behavior (timers never fire late)
- Check `saved_at` timestamp in persistence file

### High Disk I/O

- Default hourly saves should have minimal impact
- If concerned, increase `autoSaveIntervalMs` interval
- Consider using SSD storage for better performance
