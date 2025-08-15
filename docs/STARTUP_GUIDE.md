# ATous Secure Network - Startup Guide

## 🚨 IMPORTANT: Understanding Application Modes

**The ATous Secure Network has different execution modes. Not all commands start the web server!**

## 📋 Quick Reference

| What You Want | Command | Web Server? | Duration |
|---------------|---------|-------------|----------|
| **Test if installed correctly** | `python start_app.py --lite` | ❌ No | 10 seconds |
| **See system demonstration** | `python start_app.py --full` | ❌ No | 30 seconds |
| **Use the API/WebSockets** | `python start_server.py` | ✅ Yes | Continuous |
| **Access web endpoints** | `python start_server.py` | ✅ Yes | Continuous |
| **Run tests** | `python start_app.py --test` | ❌ No | 2-5 minutes |

## 🎯 Step-by-Step Startup

### Step 1: Verify Installation
```bash
python start_app.py --lite
```
**Expected:** Quick test, shows "✅ Lightweight test completed successfully!", then exits.

### Step 2: Check System Status
```bash
python start_app.py --full
```
**Expected:** Shows all systems initializing, displays status, then exits.

### Step 3: Start the Web Server
```bash
python start_server.py
```
**Expected:** Server starts and keeps running. You can now access http://localhost:8000

## 🌐 Web Server Commands

### Basic Server Start
```bash
python start_server.py
```

### Server with Custom Options
```bash
python start_server.py --host 0.0.0.0 --port 8000 --reload
```

### Using uvicorn Directly
```bash
python -m uvicorn atous_sec_network.api.server:app --host 0.0.0.0 --port 8000 --reload
```

## 📡 Testing the Running Server

Once the server is running, test these endpoints:

```bash
# Health check
curl http://localhost:8000/health

# API info
curl http://localhost:8000/api/info

# Security status
curl http://localhost:8000/api/security/status

# System metrics
curl http://localhost:8000/api/metrics

# Encrypt data
curl -X POST "http://localhost:8000/api/crypto/encrypt" \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello World", "algorithm": "AES-256"}'
```

## 🌍 Web Interface

With the server running, visit these URLs in your browser:

- **Main API**: http://localhost:8000
- **Interactive Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc
- **OpenAPI Schema**: http://localhost:8000/openapi.json

## ❌ Common Mistakes

### ❌ Wrong: Expecting `--lite` to start server
```bash
python start_app.py --lite  # This only tests imports!
```

### ❌ Wrong: Expecting `--full` to start server
```bash
python start_app.py --full  # This only shows demo!
```

### ✅ Correct: Starting the actual server
```bash
python start_server.py  # This starts the web server!
```

## 🔧 Troubleshooting

### Problem: "Connection refused" when testing endpoints
**Solution:** Make sure you started the server with `python start_server.py`

### Problem: Command exits immediately
**Solution:** This is normal for `--lite` and `--full` modes. Use `python start_server.py` for continuous operation.

### Problem: Port already in use
**Solution:** Use a different port: `python start_server.py --port 8001`

### Problem: Import errors
**Solution:** Run `python start_app.py --debug` to diagnose issues

## 🚀 Production Deployment

For production, use:

```bash
# Production server
python -m uvicorn atous_sec_network.api.server:app --host 0.0.0.0 --port 8000 --workers 4

# Or with gunicorn
gunicorn atous_sec_network.api.server:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## 📞 Need Help?

1. **Check system status**: `python start_app.py --status`
2. **Debug issues**: `python start_app.py --debug`
3. **Run tests**: `python start_app.py --test`
4. **Read logs**: Check console output for error messages
5. **Check documentation**: Visit http://localhost:8000/docs when server is running

---

**Remember: Only `python start_server.py` starts the actual web server!**