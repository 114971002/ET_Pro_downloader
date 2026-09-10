@app.get("/api/system/health")
1775: async def api_system_health(request: Request, is_authorized: None = Depends(verify_api_key)):
1776:     """API to check system metrics and Suricata running status."""
1777:     try:
1778:         # Suricata is only used for dry-run validation here, not as a local running service
1779:         suricata_running = False
1780:                     
1781:         import shutil
1782:         disk_info = {"total": "0 B", "used": "0 B", "free": "0 B", "percent": 0.0}
1783:         try:
1784:             total, used, free = shutil.disk_usage(str(app.state.project_root))
1785:             percent = (used / total) * 100 if total > 0 else 0.0
1786:             
1787:             def format_bytes(b):
1788:                 for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
1789:                     if b < 1024.0:
1790:                         return f"{b:.2f} {unit}"
1791:                     b /= 1024.0
1792:                 return f"{b:.2f} TB"
1793:                 
1794:             disk_info = {
============================================================
Match at line 1821:
1819: 
1820: 

