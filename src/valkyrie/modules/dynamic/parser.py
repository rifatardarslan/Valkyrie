import re
from typing import Dict, Any, List

def parse_strace(log_path: str) -> Dict[str, Any]:
    """Parses strace output to identify high-level behavioral activity."""
    
    results: Dict[str, Any] = {
        "file_operations": [],
        "network_operations": [],
        "execution_operations": [],
        "timeline": [],
        "raw_syscalls_count": {},
        "error": None
    }
    
    if not log_path:
        results["error"] = "Log path not provided."
        return results
        
    try:
        with open(log_path, "r", errors="ignore") as f:
            tick = 1
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                # Support basic strace formats, with or without PID/timestamps
                # e.g: [pid 1234] 10:20:30 openat(...) = 3
                # e.g: openat(...) = 3
                match = re.match(r'^(?:\[pid\s+\d+\]\s+)?(?:[\d:\.]+\s+)?([a-zA-Z0-9_]+)\((.*)\)\s*=\s*(.*)', line)
                
                if match:
                    syscall = match.group(1)
                    args = match.group(2)
                    retval = match.group(3)
                    
                    # Accumulate counts
                    results["raw_syscalls_count"][syscall] = results["raw_syscalls_count"].get(syscall, 0) + 1
                    
                    event_logged = False
                    
                    # 1. File Activity
                    if syscall in ["open", "openat"]:
                        file_match = re.search(r'"([^"]+)"', args)
                        if file_match:
                            filepath = file_match.group(1)
                            if not filepath.startswith(("/lib", "/usr/lib", "/etc/ld.so")):
                                activity = f"Opened File: {filepath}"
                                if activity not in results["file_operations"]:
                                    results["file_operations"].append(activity)
                                results["timeline"].append({"tick": tick, "action": activity, "raw": syscall})
                                event_logged = True
                                    
                    elif syscall in ["unlink", "unlinkat", "rmdir"]:
                        file_match = re.search(r'"([^"]+)"', args)
                        if file_match:
                            activity = f"Deleted File: {file_match.group(1)}"
                            results["file_operations"].append(activity)
                            results["timeline"].append({"tick": tick, "action": activity, "raw": syscall})
                            event_logged = True
                            
                    # 2. Execution / Process
                    elif syscall in ["execve"]:
                        file_match = re.search(r'"([^"]+)"', args)
                        if file_match:
                            activity = f"Executed Process: {file_match.group(1)}"
                            results["execution_operations"].append(activity)
                            results["timeline"].append({"tick": tick, "action": activity, "raw": syscall})
                            event_logged = True
                            
                    # 3. Network
                    elif syscall in ["socket", "connect", "bind", "sendto", "recvfrom"]:
                        net_match = re.search(r'sa_family=(AF_INET|AF_INET6)', args)
                        if net_match:
                            activity = f"IPv4/IPv6 Network Call: {args[:50]}..."
                            results["network_operations"].append(activity)
                            results["timeline"].append({"tick": tick, "action": activity, "raw": syscall})
                            event_logged = True
                            
                    if event_logged:
                        tick += 1
                            
    except Exception as e:
        results["error"] = str(e)
        
    return results
