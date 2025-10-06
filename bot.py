#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NumberPanel Debug Bot - Find Correct API Endpoint
"""

import os
import time
import json
import logging
import requests
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

# --- config ---
BASE_URL = os.getenv("BASE_URL", "http://51.89.99.105/NumberPanel").rstrip("/")
MANUAL_SESSION = os.getenv("MANUAL_SESSION", "2u73o492t4cr7d5tbkbcj63dv7")

# --- logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("debug-bot")

# --- session ---
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
})

if MANUAL_SESSION:
    session.cookies.set("PHPSESSID", MANUAL_SESSION)
    log.info("Using session: %s...", MANUAL_SESSION[:20])

def test_dashboard():
    """Test if we can access the dashboard"""
    try:
        url = urljoin(BASE_URL, "/client/SMSDashboard")
        log.info("🔍 Testing dashboard: %s", url)
        r = session.get(url, timeout=10)
        log.info("📊 Dashboard status: %d", r.status_code)
        
        if r.status_code == 200:
            if "login" in r.text.lower():
                log.error("❌ Got login page - session INVALID")
                return False
            else:
                log.info("✅ Dashboard accessible")
                return True
        else:
            log.error("❌ Dashboard failed: %d", r.status_code)
            return False
    except Exception as e:
        log.error("💥 Dashboard test error: %s", e)
        return False

def test_api_endpoints():
    """Test multiple possible API endpoints"""
    endpoints = [
        "/client/res/data_smscdr.php",  # Original
        "/data_smscdr.php",             # Alternative 1
        "/res/data_smscdr.php",         # Alternative 2  
        "/ajax/data_smscdr.php",        # Alternative 3
        "/api/data_smscdr.php",         # Alternative 4
        "/client/ajax/data_smscdr.php", # Alternative 5
    ]
    
    test_params = {
        "fdate1": "2025-10-06 00:00:00",
        "fdate2": "2025-10-06 23:59:59",
        "sEcho": "1",
        "iDisplayStart": "0", 
        "iDisplayLength": "5",
        "_": str(int(time.time() * 1000)),
    }
    
    headers = {
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": urljoin(BASE_URL, "/client/SMSDashboard"),
    }
    
    working_endpoints = []
    
    for endpoint in endpoints:
        try:
            url = urljoin(BASE_URL, endpoint)
            log.info("🔍 Testing: %s", url)
            r = session.get(url, params=test_params, headers=headers, timeout=10)
            
            if r.status_code == 200:
                try:
                    data = r.json()
                    log.info("✅ WORKING: %s (got JSON: %s)", endpoint, list(data.keys()) if isinstance(data, dict) else type(data))
                    working_endpoints.append(endpoint)
                except json.JSONDecodeError:
                    log.info("⚠️  Got 200 but not JSON: %s", endpoint)
            else:
                log.info("❌ Failed %d: %s", r.status_code, endpoint)
                
        except Exception as e:
            log.error("💥 Error testing %s: %s", endpoint, e)
    
    return working_endpoints

def check_session_validity():
    """Check if session cookie is valid"""
    try:
        # Test login page access
        login_url = urljoin(BASE_URL, "/login")
        r = session.get(login_url, timeout=10)
        
        if "PHPSESSID" in session.cookies:
            log.info("🍪 Session cookie: %s", session.cookies.get("PHPSESSID"))
        else:
            log.error("❌ No session cookie set")
            
        if r.status_code == 200:
            if "login" in r.text.lower() and "password" in r.text.lower():
                log.info("🔐 Can access login page")
            else:
                log.info("📄 Got page (might be redirected)")
                
    except Exception as e:
        log.error("💥 Session check error: %s", e)

def main():
    log.info("🚀 NumberPanel Debug Bot Starting...")
    log.info("🌐 Base URL: %s", BASE_URL)
    log.info("🔑 Session: %s...", MANUAL_SESSION[:20])
    
    # Step 1: Check session validity
    log.info("\n" + "="*50)
    log.info("STEP 1: Checking session validity")
    log.info("="*50)
    check_session_validity()
    
    # Step 2: Test dashboard access
    log.info("\n" + "="*50)
    log.info("STEP 2: Testing dashboard access") 
    log.info("="*50)
    dashboard_ok = test_dashboard()
    
    if not dashboard_ok:
        log.error("❌ CANNOT ACCESS DASHBOARD - Session likely expired")
        log.error("💡 Get new PHPSESSID from browser")
        return
    
    # Step 3: Test API endpoints
    log.info("\n" + "="*50)
    log.info("STEP 3: Testing API endpoints")
    log.info("="*50)
    working_endpoints = test_api_endpoints()
    
    # Step 4: Results
    log.info("\n" + "="*50)
    log.info("RESULTS")
    log.info("="*50)
    
    if working_endpoints:
        log.info("✅ WORKING ENDPOINTS:")
        for endpoint in working_endpoints:
            log.info("   - %s", endpoint)
        log.info("💡 Update your DATA_API_PATH environment variable")
    else:
        log.error("❌ NO WORKING ENDPOINTS FOUND")
        log.error("💡 Possible issues:")
        log.error("   1. Session cookie expired")
        log.error("   2. API endpoint is different")
        log.error("   3. IP blocked by server")
        log.error("   4. Website structure changed")
    
    log.info("\n🔧 NEXT STEPS:")
    log.info("   1. Get fresh PHPSESSID from browser")
    log.info("   2. Check Network tab for correct API call")
    log.info("   3. Update environment variables")

if __name__ == "__main__":
    main()
