---
name: Bug report
about: Something is broken
title: '[BUG] '
labels: bug
assignees: ''
---

**Describe the bug**
A clear description of what the bug is.

**To reproduce**
Steps to reproduce the behavior.

**Expected behavior**
What you expected to happen.

**Logs**
```
# Server: tail -f /var/log/nginx/remotepower_error.log
# Client: journalctl -u remotepower-agent -f
```

**Environment**
- Server OS:
- Client OS:
- Nginx version: `nginx -v`
- Python version: `python3 --version`
- Browser (if UI issue):
