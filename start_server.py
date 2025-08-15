#!/usr/bin/env python3
"""
ATous Secure Network - Server Starter
Starts the FastAPI web server with all security systems
"""

import sys
import argparse
from pathlib import Path

def start_server(host="127.0.0.1", port=8000, reload=False):
    """Start the FastAPI server"""
    try:
        import uvicorn
        print(f"🚀 Starting ATous Secure Network Server...")
        print(f"📡 Server will be available at: http://{host}:{port}")
        print(f"📖 API Documentation: http://{host}:{port}/docs")
        print(f"🔍 Health Check: http://{host}:{port}/health")
        print(f"🔒 Security Status: http://{host}:{port}/api/security/status")
        print("=" * 60)
        
        uvicorn.run(
            "atous_sec_network.api.server:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except ImportError:
        print("❌ Error: uvicorn not installed")
        print("Install with: pip install uvicorn[standard]")
        return 1
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        return 1

def main():
    parser = argparse.ArgumentParser(description="ATous Secure Network Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    
    args = parser.parse_args()
    
    return start_server(args.host, args.port, args.reload)

if __name__ == "__main__":
    sys.exit(main())