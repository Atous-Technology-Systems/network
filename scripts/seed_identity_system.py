#!/usr/bin/env python3
"""Seed script for the identity management system.

This script creates initial users and agents for testing and development.
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from atous_sec_network.security.identity_service import IdentityService
from atous_sec_network.security.ca_service import ProductionCAService
from atous_sec_network.core.logging_config import setup_logging

def main():
    """Main seeding function."""
    setup_logging()
    
    print("🌱 Seeding Identity Management System...")
    
    try:
        # Initialize services
        identity_service = IdentityService()
        ca_service = ProductionCAService()
        
        print("✅ Services initialized")
        
        # Create admin user
        print("\n👤 Creating admin user...")
        admin_user = identity_service.create_user(
            username="admin",
            password="admin123456",
            email="admin@atous.network",
            role="admin"
        )
        print(f"✅ Admin user created: {admin_user['username']} (ID: {admin_user['id']})")
        
        # Create operator user
        print("\n👤 Creating operator user...")
        operator_user = identity_service.create_user(
            username="operator",
            password="operator123456",
            email="operator@atous.network",
            role="operator"
        )
        print(f"✅ Operator user created: {operator_user['username']} (ID: {operator_user['id']})")
        
        # Create regular user
        print("\n👤 Creating regular user...")
        regular_user = identity_service.create_user(
            username="user",
            password="user123456",
            email="user@atous.network",
            role="user"
        )
        print(f"✅ Regular user created: {regular_user['username']} (ID: {regular_user['id']})")
        
        # Create test agents
        print("\n🤖 Creating test agents...")
        
        # Edge node agent
        edge_agent = identity_service.create_agent(
            agent_id="edge-node-001",
            name="Edge Node 001",
            agent_type="device",
            metadata={
                "location": "data-center-1",
                "capabilities": ["edge-computing", "iot-gateway"],
                "version": "1.0.0"
            }
        )
        print(f"✅ Edge agent created: {edge_agent['agent_id']}")
        
        # Service agent
        service_agent = identity_service.create_agent(
            agent_id="api-service-001",
            name="API Service 001",
            agent_type="service",
            metadata={
                "service_type": "rest-api",
                "endpoints": ["/v1/health", "/v1/status"],
                "version": "2.1.0"
            }
        )
        print(f"✅ Service agent created: {service_agent['agent_id']}")
        
        # IoT device agent
        iot_agent = identity_service.create_agent(
            agent_id="iot-sensor-001",
            name="IoT Sensor 001",
            agent_type="device",
            metadata={
                "sensor_type": "temperature",
                "location": "room-101",
                "calibration_date": "2024-01-15"
            }
        )
        print(f"✅ IoT agent created: {iot_agent['agent_id']}")
        
        # Update agent heartbeats
        print("\n💓 Updating agent heartbeats...")
        identity_service.update_agent_heartbeat("edge-node-001", {"status": "online", "cpu": 45.2})
        identity_service.update_agent_heartbeat("api-service-001", {"status": "online", "requests_per_min": 150})
        identity_service.update_agent_heartbeat("iot-sensor-001", {"status": "online", "temperature": 22.5})
        print("✅ Agent heartbeats updated")
        
        # Get system statistics
        print("\n📊 System Statistics:")
        stats = identity_service.get_system_stats()
        print(f"   Users: {stats['users']['total']}")
        print(f"   Agents: {stats['agents']['total']}")
        print(f"   Active Sessions: {stats['sessions']['active']}")
        
        # Get CA information
        print("\n🔐 CA Information:")
        ca_info = ca_service.get_ca_info()
        print(f"   CA Subject: {ca_info['ca_subject']}")
        print(f"   Total Certificates: {ca_info['total_certificates']}")
        print(f"   Policy: {ca_info['policy']['key_type']} {ca_info['policy']['key_size']} bits")
        
        print("\n🎉 Identity system seeding completed successfully!")
        print("\n📝 Login Credentials:")
        print("   Admin: admin / admin123456")
        print("   Operator: operator / operator123456")
        print("   User: user / user123456")
        print("\n⚠️  Remember to change these passwords in production!")
        
    except Exception as e:
        print(f"❌ Error seeding identity system: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
