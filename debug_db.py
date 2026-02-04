import sys
import os
import traceback

sys.path.append(os.getcwd())

try:
    from backend.core.database import db
    print("DB Imported")
    
    start = "2026-02-04 00:00:00"
    end = "2026-02-04 23:59:59"
    
    print(f"Querying timerange: {start} to {end}")
    results = db.query_security_events_by_timerange(start, end)
    print(f"Results found: {len(results)}")

except Exception as e:
    print("Caught Exception:")
    traceback.print_exc()
