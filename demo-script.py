#!/usr/bin/env python3
"""
IDROCK - IP Reputation Security Tool - Comprehensive Demonstration Script

This script demonstrates the complete IDROCK system workflow with:
1. Service health verification
2. User registration in NexShop
3. Three risk assessment scenarios (ALLOW, REVIEW, DENY)
4. Integrated login testing
5. Security history and statistics
6. Colorful logging for clear demonstration

Run with: poetry run python demo-script.py
"""

import requests
import json
import time
import sys
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
    """Print formatted risk assessment"""
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
                "name": "Scenario A: Low Risk (ALLOW)",
                "description": "Clean residential IP from trusted location",
                "data": {
                    "user_id": self.demo_user_id,
                    "ip_address": "192.168.1.100",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "session_data": {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                        "device_fingerprint": "fp_clean_residential_device",
                        "additional_data": {
                            "browser": "Chrome",
                            "screen_resolution": "1920x1080",
                            "timezone": "UTC-5",
                            "platform": "Windows"
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
                "expected_risk": "ALLOW"
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
                            "vpn_detected": True
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
                            "suspicious_patterns": ["rapid_requests", "bot_like_behavior"]
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
            }
        ]
        
        all_passed = True
        
        for i, scenario in enumerate(scenarios, 1):
            print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{scenario['name']}{Colors.ENDC}")
            print_info(scenario['description'])
            
            try:
                print_info(f"Sending request to IDROCK API...")
                response = self.session.post(
                    f"{IDROCK_URL}/api/v1/identity/verify",
                    json=scenario['data'],
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    assessment = response.json()
                    print_success(f"Risk assessment completed in {assessment.get('metadata', {}).get('processing_time_ms', 'N/A')}ms")
                    print_risk_assessment(assessment)
                    
                    # Verify expected vs actual risk level
                    actual_risk = assessment.get('risk_level')
                    expected_risk = scenario['expected_risk']
                    
                    if actual_risk == expected_risk:
                        print_success(f"Risk level matches expectation: {actual_risk}")
                    else:
                        print_warning(f"Risk level mismatch - Expected: {expected_risk}, Actual: {actual_risk}")
                    
                    # Show detailed factors
                    risk_factors = assessment.get('risk_factors', [])
                    if risk_factors:
                        print_info("Risk Factors Analysis:")
                        for factor in risk_factors:
                            details = factor.get('details', 'No details available')
                            score = factor.get('score', 0)
                            print(f"   🔍 {factor.get('factor', 'unknown')}: {score}/100 - {details}")
                    
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
                "name": "Low Risk Login",
                "headers": {"X-Forwarded-For": "192.168.1.100"},
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
                "expected_outcome": "success"
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
                f"{IDROCK_URL}/api/v1/identity/history?limit=5&user_id={self.demo_user_id}"
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
            stats_response = self.session.get(f"{IDROCK_URL}/api/v1/identity/stats?days=1")
            
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
    
    def test_api_documentation(self) -> bool:
        """Test API documentation availability"""
        print_step(6, "Testing API Documentation Access")
        
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
        print_info(f"Timestamp: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}")
        
        # Run all demonstration steps
        steps = [
            ("Service Availability", self.wait_for_services),
            ("User Registration", self.register_demo_user),
            ("Risk Assessment Scenarios", self.test_risk_scenarios),
            ("Integrated Login Testing", self.test_integrated_login),
            ("Security History & Statistics", self.view_security_history),
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