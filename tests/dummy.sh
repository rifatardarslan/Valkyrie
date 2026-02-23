#!/bin/bash
# A mock malware script meant to trigger strace file and network events.

echo "Running mock payload..."

# 1. File I/O
echo "Injecting data" > /tmp/malicious.txt
cat /etc/passwd > /dev/null

# 2. Network Activity (mocking a C2 beacon)
# We use Python as a basic mock since we installed it in the Dockerfile
python3 -c "import urllib.request; urllib.request.urlopen('http://example.com', timeout=2).read()" 2>/dev/null || true

# 3. Execution (trigger execve)
ls -la /tmp

echo "Done."
