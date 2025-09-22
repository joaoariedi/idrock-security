#!/usr/bin/env python3
"""
IDROCK - IP Reputation Security Tool - Comprehensive Demonstration Script with Advanced Security Features

This script demonstrates the complete IDROCK system workflow with:
1. Service health verification
2. User registration in NexShop
3. Enhanced risk assessment scenarios with advanced security features
4. Integrated login testing with device tracking
5. Security history and statistics
6. Advanced Security Features:
   - Device Trust Management and unique constraint validation
   - Impossible Travel Detection with geodesic calculations
   - Hardware Validation (CPU cores, RAM, screen resolution)
   - Browser Automation Detection (User-Agent patterns, headless detection)
   - Advanced device fingerprinting with Canvas/WebGL support
7. API documentation access
8. Colorful logging with enhanced security factor analysis

New Advanced Features Demonstrated:
- Device registration and trust status management
- Geolocation-based impossible travel detection
- Hardware specification validation for real computer detection
- Browser automation and headless browser detection
- Behavioral pattern analysis and temporal anomaly detection
- ASN-based network provider validation
- Enhanced risk factor weighting and scoring

Run with: poetry run python demo-script.py
"""

import requests
import json
import time
import sys
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

# Colorful console output
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(title: str):
    """Print a colorful header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{title:^60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")

def print_step(step: int, description: str):
    """Print a step with formatting"""
    print(f"\n{Colors.OKBLUE}{Colors.BOLD}Step {step}: {description}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'-'*50}{Colors.ENDC}")

def print_success(message: str, details: str = ""):
    """Print success message"""
    print(f"{Colors.OKGREEN}✅ SUCCESS: {message}{Colors.ENDC}")
    if details:
        print(f"{Colors.OKCYAN}   📋 {details}{Colors.ENDC}")

def print_warning(message: str, details: str = ""):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠️  WARNING: {message}{Colors.ENDC}")
    if details:
        print(f"{Colors.WARNING}   📋 {details}{Colors.ENDC}")

def print_error(message: str, details: str = ""):
    """Print error message"""
    print(f"{Colors.FAIL}❌ ERROR: {message}{Colors.ENDC}")
    if details:
        print(f"{Colors.FAIL}   📋 {details}{Colors.ENDC}")

def print_info(message: str):
    """Print info message"""
    print(f"{Colors.OKCYAN}ℹ️  INFO: {message}{Colors.ENDC}")

def print_risk_assessment(assessment: Dict[str, Any]):
    """Print formatted risk assessment with advanced security features"""
    risk_level = assessment.get('risk_level', 'UNKNOWN')
    confidence_score = assessment.get('confidence_score', 0)

    # Color based on risk level
    if risk_level == 'ALLOW':
        color = Colors.OKGREEN
        icon = '✅'
    elif risk_level == 'REVIEW':
        color = Colors.WARNING
        icon = '⚠️'
    else:  # DENY
        color = Colors.FAIL
        icon = '🚫'

    print(f"{color}{icon} Risk Assessment Result:{Colors.ENDC}")
    print(f"{color}   Risk Level: {risk_level}{Colors.ENDC}")
    print(f"{color}   Confidence Score: {confidence_score}/100{Colors.ENDC}")
    print(f"{color}   Request ID: {assessment.get('request_id', 'N/A')}{Colors.ENDC}")

    # Show recommendations
    recommendations = assessment.get('recommendations', [])
    if recommendations:
        print(f"{color}   Recommendations:{Colors.ENDC}")
        for rec in recommendations:
            priority_icon = '🔴' if rec.get('priority') == 'high' else '🟡' if rec.get('priority') == 'medium' else '🟢'
            print(f"{color}     {priority_icon} {rec.get('message', '')}{Colors.ENDC}")

def print_advanced_risk_factors(assessment: Dict[str, Any]):
    """Print detailed advanced security risk factors"""
    risk_factors = assessment.get('risk_factors', [])
    if not risk_factors:
        return

    print(f"\n{Colors.OKCYAN}🔍 Advanced Security Analysis:{Colors.ENDC}")

    for factor in risk_factors:
        factor_name = factor.get('factor', 'unknown')
        score = factor.get('score', 0)
        weight = factor.get('weight', 0)
        details = factor.get('details', 'No details available')
        proxycheck_data = factor.get('proxycheck_data', {})

        # Format factor display based on type
        if factor_name == 'device_trust':
            device_info = proxycheck_data
            trust_status = '🛡️ TRUSTED' if device_info.get('is_trusted') else '❓ NEW/UNTRUSTED'
            device_age = device_info.get('device_age_days', 0)
            print(f"   📱 Device Trust: {trust_status} (Age: {device_age} days, Score: {score}/100)")

        elif factor_name == 'travel_feasibility':
            travel_info = proxycheck_data
            speed = travel_info.get('travel_speed_kmh', 0)
            distance = travel_info.get('distance_km', 0)
            feasible_icon = '✈️' if travel_info.get('is_feasible') else '🚨'
            print(f"   {feasible_icon} Travel Analysis: {speed:.1f} km/h over {distance:.1f} km (Score: {score}/100)")
            if travel_info.get('previous_location'):
                prev_loc = travel_info['previous_location']
                print(f"      Previous: {prev_loc.get('country', 'Unknown')} at {prev_loc.get('timestamp', 'N/A')[:19]}")

        elif factor_name.endswith('_detected'):
            severity = proxycheck_data.get('severity', 'medium')
            severity_icon = '🔴' if severity == 'high' else '🟡' if severity == 'medium' else '🟢'
            factor_display = factor_name.replace('_detected', '').replace('_', ' ').title()
            print(f"   {severity_icon} {factor_display}: {details} (Score: {score}/100)")

        else:
            print(f"   🔍 {factor_name.replace('_', ' ').title()}: {details} (Score: {score}/100)")

def print_device_info(device_data: Dict[str, Any]):
    """Print device registration and trust information"""
    if not device_data:
        return

    print(f"\n{Colors.OKCYAN}📱 Device Information:{Colors.ENDC}")

    device = device_data.get('device', {})
    is_new = device_data.get('is_new_device', False)
    risk_assessment = device_data.get('risk_assessment', {})

    device_id = device.get('device_id', 'N/A')
    fingerprint_raw = device.get('device_fingerprint', 'N/A')
    fingerprint = (fingerprint_raw[:20] + '...') if fingerprint_raw and len(str(fingerprint_raw or '')) > 20 else str(fingerprint_raw or 'N/A')
    is_trusted = device.get('is_trusted', False)
    access_count = device.get('access_count', 0)

    status_icon = '🆕' if is_new else '🔄'
    trust_icon = '🛡️' if is_trusted else '❓'

    print(f"   {status_icon} Device ID: {device_id} ({'NEW' if is_new else 'KNOWN'})")
    print(f"   {trust_icon} Trust Status: {'TRUSTED' if is_trusted else 'UNTRUSTED'} ({access_count} accesses)")
    print(f"   🔑 Fingerprint: {fingerprint}")

    # Hardware validation
    hw_validation = risk_assessment.get('hardware_validation', {})
    if hw_validation:
        hw_valid = hw_validation.get('is_valid', False)
        hw_icon = '💻' if hw_valid else '⚠️'
        hw_issues = hw_validation.get('issues', [])
        print(f"   {hw_icon} Hardware: {'VALID' if hw_valid else 'SUSPICIOUS'} {f'({len(hw_issues)} issues)' if hw_issues else ''}")

    # Browser validation
    browser_validation = risk_assessment.get('browser_validation', {})
    if browser_validation:
        browser_valid = browser_validation.get('user_agent_legitimate', True)
        automation_detected = browser_validation.get('detected_automation', [])
        # Also check detected_patterns for backward compatibility
        if not automation_detected:
            automation_detected = browser_validation.get('detected_patterns', [])
        # Ensure automation_detected is a list
        if automation_detected is None:
            automation_detected = []
        browser_icon = '🌐' if browser_valid else '🤖'
        print(f"   {browser_icon} Browser: {'LEGITIMATE' if browser_valid else 'AUTOMATION DETECTED'}")
        if automation_detected and len(automation_detected) > 0:
            # Safely join the patterns list
            patterns_str = ', '.join(str(pattern) for pattern in automation_detected[:3] if pattern)
            if patterns_str:
                print(f"      Detected patterns: {patterns_str}")

# Service URLs
IDROCK_URL = "http://localhost:8000"
NEXSHOP_URL = "http://localhost:3000"

class IDROCKDemoRunner:
    """Main demo runner class"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 10
        self.demo_user_id = f"demouser{uuid.uuid4().hex[:8]}"
        self.demo_email = f"demo_{uuid.uuid4().hex[:8]}@idrock.com"
        self.demo_password = "SecurePassword123"
        self.demo_device_id = None  # Will be set during device registration
        
        # Get API key from environment or use default for demo
        self.idrock_api_key = os.getenv("IDROCK_API_KEY", "demo-api-key-12345")
        
        # Set default headers for IDROCK API requests
        self.idrock_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.idrock_api_key}"
        }
        
    def wait_for_services(self) -> bool:
        """Wait for both services to be available"""
        print_step(1, "Waiting for Services to Start")
        
        services = [
            (IDROCK_URL, "IDROCK Security Service", "/api/v1/health/"),
            (NEXSHOP_URL, "NexShop E-commerce Service", "/health")
        ]
        
        for url, name, health_path in services:
            print_info(f"Checking {name} at {url}...")
            
            for attempt in range(30):  # 30 attempts, 2 seconds each = 1 minute max
                try:
                    response = self.session.get(f"{url}{health_path}")
                    if response.status_code == 200:
                        health_data = response.json()
                        print_success(
                            f"{name} is healthy",
                            f"Version: {health_data.get('version', 'N/A')}, Status: {health_data.get('status', 'N/A')}"
                        )
                        break
                except requests.exceptions.RequestException:
                    pass
                
                if attempt < 29:
                    print(f"   Attempt {attempt + 1}/30 - Waiting 2 seconds...")
                    time.sleep(2)
            else:
                print_error(f"{name} is not available after 60 seconds")
                return False
        
        print_success("All services are healthy and ready!")
        return True
    
    def register_demo_user(self) -> bool:
        """Register a demo user in NexShop"""
        print_step(2, "Registering Demo User in NexShop")
        
        user_data = {
            "username": self.demo_user_id,
            "email": self.demo_email,
            "password": self.demo_password,
            "first_name": "Demo",
            "last_name": "User",
            "phone": "+1-555-123-4567"
        }
        
        try:
            print_info(f"Registering user: {self.demo_user_id}")
            response = self.session.post(
                f"{NEXSHOP_URL}/api/auth/register",
                json=user_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 201:
                user_info = response.json()
                print_success(
                    "User registered successfully",
                    f"User ID: {user_info.get('user', {}).get('id', 'N/A')}, Email: {self.demo_email}"
                )
                return True
            elif response.status_code == 409:
                print_warning("User already exists (this is expected for repeated runs)")
                return True
            else:
                print_error(f"Registration failed with status {response.status_code}", response.text[:200])
                return False
                
        except Exception as e:
            print_error("User registration failed", str(e))
            return False
    
    def test_risk_scenarios(self) -> bool:
        """Test three different risk assessment scenarios"""
        print_step(3, "Testing Risk Assessment Scenarios")
        
        scenarios = [
            {
                "name": "Scenario A: Residential IP from US (REVIEW due to new device)",
                "description": "Clean residential IP from US ISP with new device triggers REVIEW for verification",
                "data": {
                    "user_id": self.demo_user_id,
                    "ip_address": "73.162.241.5",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "session_data": {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                        "device_fingerprint": "fp_clean_residential_device",
                        "additional_data": {
                            "browser": "Chrome",
                            "screen_resolution": "1920x1080",
                            "timezone": "UTC-5",
                            "platform": "Windows",
                            "latitude": 40.7128,
                            "longitude": -74.0060,
                            "hardware_info": {
                                "cpu_cores": 8,
                                "ram_gb": 16.0,
                                "screen_resolution": "1920x1080",
                                "platform": "Win32"
                            },
                            "browser_environment": {
                                "has_plugins": True,
                                "plugin_count": 5,
                                "has_webgl": True,
                                "has_canvas": True,
                                "screen_depth": 24,
                                "languages": ["en-US", "en"]
                            }
                        }
                    },
                    "context": {
                        "action_type": "login",
                        "additional_context": {
                            "login_attempt_count": 1,
                            "last_login": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace('+00:00', 'Z')
                        }
                    }
                },
                "expected_risk": "REVIEW"  # Clean IP with new device should trigger REVIEW for verification
            },
            {
                "name": "Scenario B: Medium-High Risk (VPN/Proxy)",
                "description": "VPN/Proxy detected from different country",
                "data": {
                    "user_id": self.demo_user_id,
                    "ip_address": "45.76.97.227",
                    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "session_data": {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                        "device_fingerprint": "fp_vpn_user_device",
                        "additional_data": {
                            "browser": "Chrome",
                            "screen_resolution": "1366x768",
                            "timezone": "UTC+1",
                            "platform": "Linux",
                            "vpn_detected": True,
                            "latitude": 52.5200,
                            "longitude": 13.4050,
                            "hardware_info": {
                                "cpu_cores": 4,
                                "ram_gb": 8.0,
                                "screen_resolution": "1366x768",
                                "platform": "Linux x86_64"
                            },
                            "browser_environment": {
                                "has_plugins": True,
                                "plugin_count": 3,
                                "has_webgl": True,
                                "has_canvas": True,
                                "screen_depth": 24,
                                "languages": ["de-DE", "en"]
                            }
                        }
                    },
                    "context": {
                        "action_type": "checkout",
                        "amount": 299.99,
                        "additional_context": {
                            "cart_value": 299.99,
                            "payment_method": "credit_card",
                            "items_count": 2,
                            "first_purchase": False
                        }
                    }
                },
                "expected_risk": "DENY"  # VPN IPs are often blocked for high-risk actions
            },
            {
                "name": "Scenario C: High Risk (DENY)",
                "description": "Known malicious/hosting IP with suspicious patterns",
                "data": {
                    "user_id": self.demo_user_id,
                    "ip_address": "185.220.100.240",
                    "user_agent": "curl/7.68.0",
                    "session_data": {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                        "device_fingerprint": "fp_suspicious_automation",
                        "additional_data": {
                            "browser": "Unknown",
                            "automation_detected": True,
                            "screen_resolution": "unknown",
                            "suspicious_patterns": ["rapid_requests", "bot_like_behavior"],
                            "latitude": 37.7749,
                            "longitude": -122.4194,
                            "hardware_info": {
                                "cpu_cores": 1,
                                "ram_gb": 2.0,
                                "screen_resolution": "1024x768",
                                "platform": "Unknown"
                            },
                            "browser_environment": {
                                "has_plugins": False,
                                "plugin_count": 0,
                                "has_webgl": False,
                                "has_canvas": False,
                                "screen_depth": 16,
                                "languages": []
                            }
                        }
                    },
                    "context": {
                        "action_type": "sensitive_action",
                        "additional_context": {
                            "action": "password_reset",
                            "previous_attempts": 5,
                            "time_since_last_attempt": "30_seconds"
                        }
                    }
                },
                "expected_risk": "DENY"
            },
            {
                "name": "Scenario D: Advanced Device Fingerprinting",
                "description": "Comprehensive device fingerprinting with Canvas/WebGL/Audio features",
                "data": {
                    "user_id": self.demo_user_id,
                    "ip_address": "203.0.113.100",
                    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "session_data": {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                        "device_fingerprint": f"fp_advanced_fingerprint_{uuid.uuid4().hex[:8]}",
                        "additional_data": {
                            "browser": "Chrome",
                            "screen_resolution": "2560x1600",
                            "timezone": "UTC-8",
                            "platform": "MacIntel",
                            "latitude": 37.7749,
                            "longitude": -122.4194,
                            "hardware_info": {
                                "cpu_cores": 8,
                                "ram_gb": 32.0,
                                "screen_resolution": "2560x1600",
                                "platform": "MacIntel",
                                "timezone": "-480",
                                "language": "en-US"
                            },
                            "browser_environment": {
                                "has_plugins": True,
                                "plugin_count": 7,
                                "has_webgl": True,
                                "has_canvas": True,
                                "screen_depth": 30,
                                "languages": ["en-US", "en", "es"],
                                "navigator_properties": {
                                    "webdriver": False,
                                    "hardwareConcurrency": 8,
                                    "deviceMemory": 8,
                                    "maxTouchPoints": 0
                                },
                                "canvas_fingerprint": "sha256:a1b2c3d4e5f6...",
                                "webgl_fingerprint": "sha256:f6e5d4c3b2a1...",
                                "audio_fingerprint": "sha256:1a2b3c4d5e6f..."
                            }
                        }
                    },
                    "context": {
                        "action_type": "login",
                        "additional_context": {
                            "login_method": "password",
                            "device_remembered": False,
                            "2fa_enabled": True
                        }
                    }
                },
                "expected_risk": "ALLOW"
            }
        ]
        
        all_passed = True
        
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{scenario['name']}{Colors.ENDC}")
            print_info(scenario['description'])

            # Add special handling for advanced fingerprinting scenario
            if "fingerprinting" in scenario['name'].lower():
                print_info("This scenario demonstrates advanced device fingerprinting capabilities:")
                browser_env = scenario['data']['session_data']['additional_data'].get('browser_environment', {})
                if browser_env.get('canvas_fingerprint'):
                    print(f"   🎨 Canvas Fingerprint: {browser_env['canvas_fingerprint'][:20]}...")
                if browser_env.get('webgl_fingerprint'):
                    print(f"   🎮 WebGL Fingerprint: {browser_env['webgl_fingerprint'][:20]}...")
                if browser_env.get('audio_fingerprint'):
                    print(f"   🔊 Audio Fingerprint: {browser_env['audio_fingerprint'][:20]}...")
                print(f"   🧠 Hardware Concurrency: {browser_env.get('navigator_properties', {}).get('hardwareConcurrency', 'N/A')} cores")
                print(f"   💾 Device Memory: {browser_env.get('navigator_properties', {}).get('deviceMemory', 'N/A')} GB")

            try:
                print_info(f"Sending request to IDROCK API with authentication...")
                response = self.session.post(
                    f"{IDROCK_URL}/api/v1/identity/verify",
                    json=scenario['data'],
                    headers=self.idrock_headers
                )
                
                if response.status_code == 200:
                    assessment = response.json()
                    print_success(f"Risk assessment completed in {assessment.get('metadata', {}).get('processing_time_ms', 'N/A')}ms")
                    print_risk_assessment(assessment)

                    # Show advanced security analysis
                    print_advanced_risk_factors(assessment)

                    # Verify expected vs actual risk level
                    actual_risk = assessment.get('risk_level')
                    expected_risk = scenario['expected_risk']

                    if actual_risk == expected_risk:
                        print_success(f"Risk level matches expectation: {actual_risk}")
                    else:
                        print_warning(f"Risk level mismatch - Expected: {expected_risk}, Actual: {actual_risk}")

                    # Show detailed factors with enhanced formatting
                    risk_factors = assessment.get('risk_factors', [])
                    if risk_factors:
                        print_info("Detailed Risk Factors Analysis:")
                        for factor in risk_factors:
                            factor_name = factor.get('factor', 'unknown')
                            details = factor.get('details', 'No details available')
                            score = factor.get('score', 0)
                            weight = factor.get('weight', 0)
                            print(f"   🔍 {factor_name.replace('_', ' ').title()}: {score}/100 (weight: {weight:.1f})")
                            print(f"      {details}")
                    
                else:
                    print_error(f"API request failed with status {response.status_code}", response.text[:200])
                    all_passed = False
                
            except Exception as e:
                print_error(f"Scenario {i} failed", str(e))
                all_passed = False
            
            # Brief pause between scenarios
            if i < len(scenarios):
                time.sleep(2)
        
        return all_passed
    
    def test_integrated_login(self) -> bool:
        """Test integrated login with different risk scenarios"""
        print_step(4, "Testing Integrated Login (NexShop + IDROCK)")
        
        login_scenarios = [
            {
                "name": "Residential IP Login with New Device (Expected Review)",
                "headers": {"X-Forwarded-For": "73.162.241.5"},
                "data": {
                    "username": self.demo_user_id,
                    "password": self.demo_password,
                    "deviceFingerprint": "fp_trusted_device_chrome",
                    "sessionData": {
                        "browser": "Chrome",
                        "screen_resolution": "1920x1080",
                        "platform": "Windows",
                        "timezone": "America/New_York"
                    },
                    "additionalData": {
                        "login_source": "web_app"
                    }
                },
                "expected_outcome": "additional_verification"  # New devices trigger review for additional verification
            },
            {
                "name": "High Risk Login (VPN) - Expected Block",
                "headers": {"X-Forwarded-For": "45.76.97.227"},
                "data": {
                    "username": self.demo_user_id,
                    "password": self.demo_password,
                    "deviceFingerprint": "fp_vpn_device",
                    "sessionData": {
                        "browser": "Firefox",
                        "screen_resolution": "1366x768",
                        "platform": "Linux",
                        "timezone": "Europe/London"
                    },
                    "additionalData": {
                        "login_source": "mobile_app"
                    }
                },
                "expected_outcome": "blocked_or_additional_verification"
            }
        ]
        
        all_passed = True
        
        for scenario in login_scenarios:
            print(f"\n{Colors.BOLD}{scenario['name']}{Colors.ENDC}")
            
            try:
                print_info("Attempting integrated login...")
                response = self.session.post(
                    f"{NEXSHOP_URL}/api/auth/login",
                    json=scenario['data'],
                    headers={**{"Content-Type": "application/json"}, **scenario['headers']}
                )
                
                if response.status_code == 200:
                    login_result = response.json()
                    security_info = login_result.get('security', {})
                    
                    print_success(
                        "Login successful with IDROCK protection",
                        f"Risk Level: {security_info.get('risk_level', 'N/A')}, "
                        f"Confidence: {security_info.get('confidence_score', 'N/A')}/100"
                    )
                    
                    if security_info:
                        print_info(f"Security Assessment Request ID: {security_info.get('request_id', 'N/A')}")
                        print_info(f"IDROCK Service Available: {security_info.get('service_available', 'N/A')}")
                    
                elif response.status_code == 202:
                    login_result = response.json()
                    risk_info = login_result.get('risk_assessment', {})

                    if scenario['expected_outcome'] == 'additional_verification':
                        print_success(
                            "Login correctly requires additional verification",
                            f"Risk Level: {risk_info.get('risk_level', 'N/A')}, "
                            f"Confidence: {risk_info.get('confidence_score', 'N/A')}/100"
                        )
                    else:
                        print_warning(
                            "Login requires additional verification",
                            f"Risk Level: {risk_info.get('risk_level', 'N/A')}, "
                            f"Confidence: {risk_info.get('confidence_score', 'N/A')}/100"
                        )

                    verification_methods = login_result.get('verification_methods', [])
                    print_info(f"Available verification methods: {', '.join(verification_methods)}")

                    security_reasons = login_result.get('security_reasons', [])
                    if security_reasons:
                        print_info(f"Security concerns: {', '.join(security_reasons)}")
                
                elif response.status_code == 403:
                    # Handle blocked login as expected for high-risk scenarios
                    if scenario['expected_outcome'] == 'blocked_or_additional_verification':
                        login_result = response.json()
                        risk_level = login_result.get('riskLevel', 'UNKNOWN')
                        request_id = login_result.get('requestId', 'N/A')
                        
                        print_success(
                            "Login correctly blocked by IDROCK security system",
                            f"Risk Level: {risk_level}, Request ID: {request_id}"
                        )
                        print_info("This demonstrates IDROCK protection working as intended for high-risk IPs")
                    else:
                        print_error(f"Unexpected login block with status {response.status_code}", response.text[:200])
                        all_passed = False
                
                else:
                    print_error(f"Login failed with status {response.status_code}", response.text[:200])
                    all_passed = False
                
            except Exception as e:
                print_error(f"Login scenario failed: {scenario['name']}", str(e))
                all_passed = False
            
            time.sleep(1)
        
        return all_passed
    
    def view_security_history(self) -> bool:
        """View assessment history and statistics"""
        print_step(5, "Viewing Security History and Statistics")
        
        try:
            # Get recent assessment history
            print_info("Fetching recent assessment history...")
            history_response = self.session.get(
                f"{IDROCK_URL}/api/v1/identity/history?limit=5&user_id={self.demo_user_id}",
                headers=self.idrock_headers
            )
            
            if history_response.status_code == 200:
                history_data = history_response.json()
                assessments = history_data.get('assessments', [])
                
                print_success(f"Retrieved {len(assessments)} recent assessments for demo user")
                
                if assessments:
                    print_info("Recent Assessment History:")
                    for i, assessment in enumerate(assessments, 1):
                        risk_level = assessment.get('risk_level', 'UNKNOWN')
                        confidence = assessment.get('confidence_score', 0)
                        action = assessment.get('action_type', 'N/A')
                        timestamp = assessment.get('created_at', 'N/A')
                        
                        # Color based on risk level
                        if risk_level == 'ALLOW':
                            color = Colors.OKGREEN
                        elif risk_level == 'REVIEW':
                            color = Colors.WARNING
                        else:
                            color = Colors.FAIL
                        
                        print(f"   {color}{i}. {risk_level} ({confidence}/100) - {action} at {timestamp}{Colors.ENDC}")
                else:
                    print_info("No assessments found for demo user (this may occur if assessments are still processing)")
            
            # Get overall statistics
            print_info("Fetching overall security statistics...")
            stats_response = self.session.get(
                f"{IDROCK_URL}/api/v1/identity/stats?days=1",
                headers=self.idrock_headers
            )
            
            if stats_response.status_code == 200:
                stats_data = stats_response.json()
                
                print_success("Security statistics retrieved")
                print_info(f"Total assessments (24h): {stats_data.get('total_assessments', 0)}")
                
                risk_dist = stats_data.get('risk_distribution', {})
                if risk_dist:
                    print_info("Risk level distribution:")
                    print(f"   {Colors.OKGREEN}✅ ALLOW: {risk_dist.get('ALLOW', 0)}{Colors.ENDC}")
                    print(f"   {Colors.WARNING}⚠️  REVIEW: {risk_dist.get('REVIEW', 0)}{Colors.ENDC}")
                    print(f"   {Colors.FAIL}🚫 DENY: {risk_dist.get('DENY', 0)}{Colors.ENDC}")
                
                avg_confidence = stats_data.get('average_confidence_score', 0)
                print_info(f"Average confidence score: {avg_confidence}/100")
                
                most_common = stats_data.get('most_common_action', 'N/A')
                print_info(f"Most common action type: {most_common}")
            
            # Get NexShop authentication statistics
            print_info("Fetching NexShop authentication statistics...")
            nexshop_stats_response = self.session.get(f"{NEXSHOP_URL}/api/auth/stats")
            
            if nexshop_stats_response.status_code == 200:
                nexshop_stats = nexshop_stats_response.json()
                auth_stats = nexshop_stats.get('auth_stats', {})
                sdk_stats = nexshop_stats.get('idrock_sdk_stats', {})
                
                print_success("NexShop authentication statistics retrieved")
                print_info(f"Login attempts (24h): {auth_stats.get('total_attempts_24h', 0)}")
                print_info(f"Successful logins (24h): {auth_stats.get('successful_logins_24h', 0)}")
                print_info(f"Blocked attempts (24h): {auth_stats.get('blocked_attempts_24h', 0)}")
                
                if sdk_stats:
                    print_info(f"IDROCK SDK requests: {sdk_stats.get('total_requests', 0)}")
                    print_info(f"SDK success rate: {sdk_stats.get('service_uptime', 'N/A')}")
                    avg_response_time = sdk_stats.get('average_response_time_ms', 0)
                    print_info(f"Average response time: {avg_response_time}ms")
            
            return True
            
        except Exception as e:
            print_error("Failed to retrieve security statistics", str(e))
            return False
    
    def test_advanced_security_features(self) -> bool:
        """Test advanced security features including device management and behavioral analysis"""
        print_step(6, "Testing Advanced Security Features")

        all_passed = True

        # Test device registration and management
        device_test_passed = self.test_device_management()
        all_passed = all_passed and device_test_passed

        # Test impossible travel detection
        travel_test_passed = self.test_impossible_travel_detection()
        all_passed = all_passed and travel_test_passed

        # Test hardware and browser validation
        validation_test_passed = self.test_hardware_browser_validation()
        all_passed = all_passed and validation_test_passed

        return all_passed

    def test_device_management(self) -> bool:
        """Test device registration, tracking, and trust management"""
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Device Trust Management Demonstration{Colors.ENDC}")

        try:
            # Scenario D: New Device Registration
            print_info("Registering a new device for the demo user...")

            device_data = {
                "user_id": self.demo_user_id,
                "device_fingerprint": f"fp_demo_device_{uuid.uuid4().hex[:12]}",
                "hardware_info": {
                    "cpu_cores": 8,
                    "ram_gb": 16.0,
                    "screen_resolution": "2560x1440",
                    "platform": "Win32",
                    "timezone": "-300",
                    "language": "en-US"
                },
                "browser_info": {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "has_plugins": True,
                    "plugin_count": 5,
                    "has_webgl": True,
                    "has_canvas": True,
                    "screen_depth": 24,
                    "languages": ["en-US", "en"]
                }
            }

            response = self.session.post(
                f"{IDROCK_URL}/api/v1/devices/register",
                json=device_data,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                device_result = response.json()
                print_success("Device registered successfully")
                print_device_info(device_result)

                # Store device ID for later tests
                self.demo_device_id = device_result.get('device', {}).get('device_id')

                # Test device listing
                print_info("\nListing user devices...")
                list_response = self.session.get(f"{IDROCK_URL}/api/v1/devices/list/{self.demo_user_id}")

                if list_response.status_code == 200:
                    device_list = list_response.json()
                    devices = device_list.get('devices', [])
                    trusted_count = device_list.get('trusted_devices', 0)

                    print_success(f"Retrieved {len(devices)} devices ({trusted_count} trusted)")
                    for device in devices[:3]:  # Show first 3 devices
                        device_fp = device.get('device_fingerprint', 'N/A')[:20] + '...'
                        trust_status = 'TRUSTED' if device.get('is_trusted') else 'UNTRUSTED'
                        access_count = device.get('access_count', 0)
                        print(f"   📱 Device {device.get('device_id')}: {trust_status} ({access_count} accesses)")
                        print(f"      Fingerprint: {device_fp}")

                return True
            else:
                print_error(f"Device registration failed with status {response.status_code}", response.text[:200])
                return False

        except Exception as e:
            print_error("Device management test failed", str(e))
            return False

    def test_impossible_travel_detection(self) -> bool:
        """Test impossible travel detection with geographic analysis"""
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Impossible Travel Detection Demonstration{Colors.ENDC}")

        if not hasattr(self, 'demo_device_id') or not self.demo_device_id:
            print_warning("Skipping travel detection test - no device registered")
            return True

        try:
            # First access from New York
            print_info("Logging device access from New York...")

            ny_access = {
                "device_id": self.demo_device_id,
                "ip_address": "192.168.1.100",
                "location_data": {
                    "lat": 40.7128,
                    "lng": -74.0060,
                    "country": "US",
                    "city": "New York"
                },
                "asn": "AS7922",
                "hardware_info": {
                    "cpu_cores": 8,
                    "ram_gb": 16.0
                }
            }

            response = self.session.post(
                f"{IDROCK_URL}/api/v1/devices/access",
                json=ny_access,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                access_result = response.json()
                print_success("New York access logged successfully")

                # Brief pause to simulate time passage
                time.sleep(2)

                # Second access from Tokyo (impossible travel)
                print_info("\nAttempting access from Tokyo 2 minutes later (impossible travel)...")

                tokyo_access = {
                    "device_id": self.demo_device_id,
                    "ip_address": "203.0.113.50",
                    "location_data": {
                        "lat": 35.6762,
                        "lng": 139.6503,
                        "country": "JP",
                        "city": "Tokyo"
                    },
                    "asn": "AS2516",
                    "hardware_info": {
                        "cpu_cores": 8,
                        "ram_gb": 16.0
                    }
                }

                tokyo_response = self.session.post(
                    f"{IDROCK_URL}/api/v1/devices/access",
                    json=tokyo_access,
                    headers={"Content-Type": "application/json"}
                )

                if tokyo_response.status_code == 200:
                    tokyo_result = tokyo_response.json()
                    travel_analysis = tokyo_result.get('travel_analysis', {})

                    if travel_analysis:
                        speed = travel_analysis.get('travel_speed_kmh', 0)
                        distance = travel_analysis.get('distance_km', 0)
                        feasible = travel_analysis.get('is_feasible', True)

                        if not feasible:
                            print_success(f"Impossible travel detected! Speed: {speed:.1f} km/h over {distance:.1f} km")
                            print_info(f"Risk level: {travel_analysis.get('risk_level', 'UNKNOWN')}")
                        else:
                            print_warning("Travel analysis did not detect impossible travel (unexpected)")
                    else:
                        print_warning("No travel analysis data returned")

                return True
            else:
                print_error(f"Access logging failed with status {response.status_code}", response.text[:200])
                return False

        except Exception as e:
            print_error("Travel detection test failed", str(e))
            return False

    def test_hardware_browser_validation(self) -> bool:
        """Test hardware and browser validation features"""
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}Hardware & Browser Validation Demonstration{Colors.ENDC}")

        scenarios = [
            {
                "name": "Insufficient Hardware Detection",
                "description": "Device with insufficient CPU and RAM",
                "data": {
                    "user_id": self.demo_user_id,
                    "device_fingerprint": f"fp_weak_device_{uuid.uuid4().hex[:8]}",
                    "hardware_info": {
                        "cpu_cores": 1,  # Below minimum
                        "ram_gb": 2.0,   # Below minimum
                        "screen_resolution": "800x600",
                        "platform": "Win32"
                    }
                },
                "expected": "hardware validation failure"
            },
            {
                "name": "Automation Tool Detection",
                "description": "Browser automation detected via User-Agent",
                "data": {
                    "user_id": self.demo_user_id,
                    "device_fingerprint": f"fp_automation_{uuid.uuid4().hex[:8]}",
                    "browser_info": {
                        "user_agent": "selenium/4.0.0 (automated browser)",
                        "has_plugins": False,
                        "plugin_count": 0,
                        "has_webgl": False,
                        "has_canvas": True,
                        "screen_depth": 24,
                        "languages": []
                    }
                },
                "expected": "automation detection"
            }
        ]

        all_passed = True

        for scenario in scenarios:
            print(f"\n   Testing: {scenario['name']}")
            print_info(scenario['description'])

            try:
                response = self.session.post(
                    f"{IDROCK_URL}/api/v1/devices/register",
                    json=scenario['data'],
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    result = response.json()
                    risk_assessment = result.get('risk_assessment', {})

                    print_success(f"Validation completed - demonstrating {scenario['expected']}")
                    print_device_info(result)

                else:
                    print_error(f"Validation test failed with status {response.status_code}", response.text[:200])
                    all_passed = False

            except Exception as e:
                print_error(f"Hardware/browser validation test failed: {scenario['name']}", str(e))
                all_passed = False

        return all_passed

    def test_api_documentation(self) -> bool:
        """Test API documentation availability"""
        print_step(7, "Testing API Documentation Access")

        try:
            # Test Swagger UI
            print_info("Checking Swagger UI documentation...")
            docs_response = self.session.get(f"{IDROCK_URL}/docs")

            if docs_response.status_code == 200:
                print_success("Swagger UI documentation is available")
                print_info(f"Access at: {IDROCK_URL}/docs")
            else:
                print_warning(f"Swagger UI not available (status: {docs_response.status_code})")

            # Test OpenAPI specification
            print_info("Checking OpenAPI specification...")
            openapi_response = self.session.get(f"{IDROCK_URL}/openapi.json")

            if openapi_response.status_code == 200:
                openapi_spec = openapi_response.json()
                print_success("OpenAPI specification is available")
                print_info(f"API Version: {openapi_spec.get('info', {}).get('version', 'N/A')}")
                print_info(f"API Title: {openapi_spec.get('info', {}).get('title', 'N/A')}")
                print_info(f"Access at: {IDROCK_URL}/openapi.json")
            else:
                print_warning(f"OpenAPI spec not available (status: {openapi_response.status_code})")

            return True

        except Exception as e:
            print_error("Failed to check API documentation", str(e))
            return False
    
    def run_complete_demo(self) -> bool:
        """Run the complete demonstration"""
        print_header("IDROCK - IP Reputation Security Tool - Complete Demonstration")
        
        print_info(f"Demo User ID: {self.demo_user_id}")
        print_info(f"Demo Email: {self.demo_email}")
        print_info(f"Target Services: IDROCK ({IDROCK_URL}) + NexShop ({NEXSHOP_URL})")
        print_info(f"IDROCK API Key: {self.idrock_api_key[:12]}... (configured from IDROCK_API_KEY env var)")
        print_info(f"Timestamp: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}")
        
        # Run all demonstration steps
        steps = [
            ("Service Availability", self.wait_for_services),
            ("User Registration", self.register_demo_user),
            ("Risk Assessment Scenarios", self.test_risk_scenarios),
            ("Integrated Login Testing", self.test_integrated_login),
            ("Security History & Statistics", self.view_security_history),
            ("Advanced Security Features", self.test_advanced_security_features),
            ("API Documentation", self.test_api_documentation)
        ]
        
        results = []
        
        for step_name, step_func in steps:
            try:
                result = step_func()
                results.append(result)
                
                if result:
                    print_success(f"✅ {step_name} completed successfully")
                else:
                    print_error(f"❌ {step_name} failed")
                
            except Exception as e:
                print_error(f"❌ {step_name} failed with exception", str(e))
                results.append(False)
            
            # Brief pause between major steps
            time.sleep(1)
        
        # Print final summary
        print_header("Demonstration Summary")
        
        passed = sum(results)
        total = len(results)
        success_rate = (passed / total) * 100 if total > 0 else 0
        
        print(f"\n{Colors.BOLD}Results Summary:{Colors.ENDC}")
        print(f"   Steps Completed: {passed}/{total}")
        print(f"   Success Rate: {success_rate:.1f}%")
        
        if passed == total:
            print_success("🎉 ALL DEMONSTRATION STEPS COMPLETED SUCCESSFULLY!")
            print_info("The IDROCK security system is fully operational and integrated.")
            
            print(f"\n{Colors.BOLD}Next Steps:{Colors.ENDC}")
            print(f"   • Access API docs: {IDROCK_URL}/docs")
            print(f"   • Monitor security logs and statistics")
            print(f"   • Test with your own applications")
            print(f"   • Review the IDROCK_DEMO_GUIDE.md for manual testing")
            
        else:
            print_warning(f"⚠️  {total - passed} STEPS FAILED - Check the output above for details")
            
            print(f"\n{Colors.BOLD}Troubleshooting:{Colors.ENDC}")
            print("   • Ensure Docker containers are running: docker-compose ps")
            print("   • Check service logs: docker-compose logs")
            print("   • Verify environment variables")
            print("   • Check network connectivity")
        
        return passed == total

def main():
    """Main entry point"""
    try:
        demo = IDROCKDemoRunner()
        success = demo.run_complete_demo()
        
        print(f"\n{Colors.BOLD}Demonstration completed at {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}{Colors.ENDC}")
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}⏹️  Demonstration interrupted by user{Colors.ENDC}")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n{Colors.FAIL}❌ Demonstration failed with unexpected error: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()