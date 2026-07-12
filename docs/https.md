# HTTPS / TLS termination

### With acme.sh

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name power.yourdomain.com;

    ssl_certificate     /root/.acme.sh/yourdomain.com/fullchain.cer;
    ssl_certificate_key /root/.acme.sh/yourdomain.com/yourdomain.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /var/www/remotepower;
    index index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:8090;   # gunicorn + wsgi.py (the app server)
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # Long-poll exec needs an extended timeout
        proxy_read_timeout 130s;
        limit_except GET POST DELETE PATCH { deny all; }
    }

    location /agent/ {
        root /var/www/remotepower;
        add_header Content-Disposition 'attachment; filename=remotepower-agent';
        add_header Content-Type application/octet-stream;
    }

    location / { try_files $uri $uri/ /index.html; }
    location ~* \.(json|tmp)$ { deny all; }
}
```

> **Note:** `proxy_read_timeout 130s` is required for `/api/exec/wait` long-poll connections. Without it, Nginx will close the connection after the default 60 s.

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
