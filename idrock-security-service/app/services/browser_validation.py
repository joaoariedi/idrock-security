import re
from typing import Dict, Any, List, Optional


class BrowserValidationService:
    """Service for detecting automation tools and validating real browsers"""

    # Blacklisted User-Agent patterns for automation tools
    AUTOMATION_PATTERNS = [
        # Command-line tools
        r'wget',
        r'curl',
        r'httpie',
        r'aria2',

        # Python tools
        r'python-requests',
        r'python-urllib',
        r'python-httpx',
        r'python/\d+\.\d+',

        # Browser automation
        r'selenium',
        r'webdriver',
        r'puppeteer',
        r'playwright',
        r'phantomjs',
        r'headlesschrome',
        r'chromedriver',
        r'geckodriver',

        # Scraping tools
        r'scrapy',
        r'beautifulsoup',
        r'mechanize',
        r'requests-html',

        # Other automation
        r'robot',
        r'crawler',
        r'spider',
        r'bot(?!.*mobile)',  # Bot but not mobile
        r'automated',
        r'headless',

        # Suspicious browsers
        r'htmlunit',
        r'zombie\.js',
        r'jsdom',
    ]

    @staticmethod
    def validate_user_agent(user_agent: str) -> Dict[str, Any]:
        """
        Validate User-Agent string for automation tools and suspicious patterns.

        Args:
            user_agent: User-Agent header string

        Returns:
            Dict containing validation results:
            {
                "is_legitimate": bool,
                "risk_level": str,  # "ALLOW", "REVIEW"
                "detected_patterns": list,
                "browser_info": dict,
                "risk_factors": dict
            }
        """
        if not user_agent:
            return {
                "is_legitimate": False,
                "risk_level": "REVIEW",
                "detected_patterns": ["missing_user_agent"],
                "browser_info": {},
                "risk_factors": {
                    "missing_user_agent": {
                        "detected": True,
                        "severity": "high",
                        "description": "No User-Agent header provided"
                    }
                }
            }

        detected_patterns = []
        risk_factors = {}
        browser_info = BrowserValidationService._extract_browser_info(user_agent)

        # Check against automation patterns
        user_agent_lower = user_agent.lower()
        for pattern in BrowserValidationService.AUTOMATION_PATTERNS:
            if re.search(pattern, user_agent_lower):
                detected_patterns.append(pattern)

        # Additional suspicious patterns
        suspicious_checks = BrowserValidationService._check_suspicious_patterns(user_agent, user_agent_lower)
        detected_patterns.extend(suspicious_checks["patterns"])
        risk_factors.update(suspicious_checks["risk_factors"])

        # Determine legitimacy
        is_legitimate = len(detected_patterns) == 0
        risk_level = "REVIEW" if not is_legitimate else "ALLOW"

        # Add automation detection risk factors
        if detected_patterns:
            risk_factors["automation_detected"] = {
                "detected": True,
                "severity": "high",
                "description": f"Automation tools detected: {', '.join(detected_patterns[:3])}"
            }

        return {
            "is_legitimate": is_legitimate,
            "risk_level": risk_level,
            "detected_patterns": detected_patterns,
            "browser_info": browser_info,
            "risk_factors": risk_factors
        }

    @staticmethod
    def validate_browser_environment(browser_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate browser environment data for headless detection.

        Args:
            browser_info: Dictionary containing browser environment data:
                {
                    "has_plugins": bool,
                    "plugin_count": int,
                    "has_webgl": bool,
                    "has_canvas": bool,
                    "screen_depth": int,
                    "languages": list,
                    "timezone": str,
                    "navigator_properties": dict
                }

        Returns:
            Dict containing validation results
        """
        if not browser_info:
            return {
                "is_real_browser": False,
                "risk_level": "REVIEW",
                "validation_details": {
                    "reason": "no_browser_environment_data",
                    "message": "No browser environment data provided"
                },
                "risk_factors": {
                    "missing_browser_data": {
                        "detected": True,
                        "severity": "medium",
                        "description": "Client did not provide browser environment data"
                    }
                }
            }

        risk_factors = {}
        issues = []

        # Check for headless indicators
        if not browser_info.get("has_plugins", True):
            issues.append("No browser plugins detected")
            risk_factors["no_plugins"] = {
                "detected": True,
                "severity": "medium",
                "description": "Browser reports no plugins (typical of headless browsers)"
            }

        plugin_count = browser_info.get("plugin_count", 0)
        if plugin_count == 0:
            issues.append("Zero plugins reported")
            risk_factors["zero_plugins"] = {
                "detected": True,
                "severity": "medium",
                "description": "Browser reports exactly zero plugins"
            }

        # WebGL and Canvas support
        if not browser_info.get("has_webgl", True):
            issues.append("WebGL not supported")
            risk_factors["no_webgl"] = {
                "detected": True,
                "severity": "low",
                "description": "Browser does not support WebGL"
            }

        if not browser_info.get("has_canvas", True):
            issues.append("Canvas not supported")
            risk_factors["no_canvas"] = {
                "detected": True,
                "severity": "medium",
                "description": "Browser does not support Canvas"
            }

        # Screen depth check
        screen_depth = browser_info.get("screen_depth")
        if screen_depth is not None and screen_depth not in [16, 24, 32]:
            issues.append(f"Unusual screen depth: {screen_depth}")
            risk_factors["unusual_screen_depth"] = {
                "detected": True,
                "severity": "low",
                "description": f"Unusual screen color depth: {screen_depth}"
            }

        # Language validation
        languages = browser_info.get("languages", [])
        if not languages or len(languages) == 0:
            issues.append("No languages detected")
            risk_factors["no_languages"] = {
                "detected": True,
                "severity": "medium",
                "description": "Browser reports no supported languages"
            }

        # Navigator properties validation
        nav_props = browser_info.get("navigator_properties", {})
        if nav_props:
            nav_issues = BrowserValidationService._validate_navigator_properties(nav_props)
            issues.extend(nav_issues["issues"])
            risk_factors.update(nav_issues["risk_factors"])

        # Determine overall assessment
        critical_issues = sum(1 for factor in risk_factors.values() if factor.get("severity") == "high")
        medium_issues = sum(1 for factor in risk_factors.values() if factor.get("severity") == "medium")

        is_real_browser = critical_issues == 0 and medium_issues < 3
        risk_level = "REVIEW" if not is_real_browser else "ALLOW"

        return {
            "is_real_browser": is_real_browser,
            "risk_level": risk_level,
            "validation_details": {
                "issues": issues,
                "critical_issues": critical_issues,
                "medium_issues": medium_issues,
                "browser_summary": {
                    "has_plugins": browser_info.get("has_plugins"),
                    "plugin_count": plugin_count,
                    "has_webgl": browser_info.get("has_webgl"),
                    "has_canvas": browser_info.get("has_canvas"),
                    "language_count": len(languages)
                }
            },
            "risk_factors": risk_factors
        }

    @staticmethod
    def _extract_browser_info(user_agent: str) -> Dict[str, Any]:
        """Extract browser information from User-Agent string"""
        browser_info = {
            "raw_user_agent": user_agent,
            "browser": "unknown",
            "version": "unknown",
            "platform": "unknown"
        }

        # Basic browser detection
        if "Chrome" in user_agent:
            browser_info["browser"] = "Chrome"
            chrome_match = re.search(r'Chrome/(\d+\.\d+)', user_agent)
            if chrome_match:
                browser_info["version"] = chrome_match.group(1)

        elif "Firefox" in user_agent:
            browser_info["browser"] = "Firefox"
            firefox_match = re.search(r'Firefox/(\d+\.\d+)', user_agent)
            if firefox_match:
                browser_info["version"] = firefox_match.group(1)

        elif "Safari" in user_agent and "Chrome" not in user_agent:
            browser_info["browser"] = "Safari"
            safari_match = re.search(r'Version/(\d+\.\d+)', user_agent)
            if safari_match:
                browser_info["version"] = safari_match.group(1)

        elif "Edge" in user_agent:
            browser_info["browser"] = "Edge"
            edge_match = re.search(r'Edge/(\d+\.\d+)', user_agent)
            if edge_match:
                browser_info["version"] = edge_match.group(1)

        # Platform detection
        if "Windows" in user_agent:
            browser_info["platform"] = "Windows"
        elif "Macintosh" in user_agent:
            browser_info["platform"] = "macOS"
        elif "Linux" in user_agent:
            browser_info["platform"] = "Linux"
        elif "Android" in user_agent:
            browser_info["platform"] = "Android"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            browser_info["platform"] = "iOS"

        return browser_info

    @staticmethod
    def _check_suspicious_patterns(user_agent: str, user_agent_lower: str) -> Dict[str, Any]:
        """Check for additional suspicious patterns in User-Agent"""
        patterns = []
        risk_factors = {}

        # Check for very short User-Agent
        if len(user_agent) < 20:
            patterns.append("very_short_user_agent")
            risk_factors["short_user_agent"] = {
                "detected": True,
                "severity": "medium",
                "description": f"Unusually short User-Agent: {len(user_agent)} characters"
            }

        # Check for missing standard components
        if "Mozilla" not in user_agent:
            patterns.append("missing_mozilla")
            risk_factors["missing_mozilla"] = {
                "detected": True,
                "severity": "low",
                "description": "User-Agent missing 'Mozilla' component"
            }

        # Check for suspicious version patterns
        if re.search(r'\d{4,}', user_agent):  # Very high version numbers
            patterns.append("suspicious_version_numbers")
            risk_factors["suspicious_versions"] = {
                "detected": True,
                "severity": "low",
                "description": "User-Agent contains unusually high version numbers"
            }

        return {
            "patterns": patterns,
            "risk_factors": risk_factors
        }

    @staticmethod
    def _validate_navigator_properties(nav_props: Dict[str, Any]) -> Dict[str, Any]:
        """Validate navigator properties for consistency"""
        issues = []
        risk_factors = {}

        # Check for webdriver property (automation indicator)
        if nav_props.get("webdriver") is True:
            issues.append("WebDriver property detected")
            risk_factors["webdriver_detected"] = {
                "detected": True,
                "severity": "high",
                "description": "Navigator.webdriver property is true (automation tool)"
            }

        # Check for automation-specific properties
        automation_props = ["_phantom", "_selenium", "__webdriver_script_fn"]
        for prop in automation_props:
            if nav_props.get(prop) is not None:
                issues.append(f"Automation property detected: {prop}")
                risk_factors[f"automation_prop_{prop}"] = {
                    "detected": True,
                    "severity": "high",
                    "description": f"Automation tool property detected: {prop}"
                }

        return {
            "issues": issues,
            "risk_factors": risk_factors
        }

    @staticmethod
    def get_browser_risk_factors(
        user_agent: str,
        browser_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive browser risk factors for integration with risk engine.

        Returns risk factors that can be integrated into the main risk assessment.
        """
        # Validate User-Agent
        ua_validation = BrowserValidationService.validate_user_agent(user_agent)

        # Validate browser environment if provided
        env_validation = BrowserValidationService.validate_browser_environment(browser_info)

        # Combine risk factors
        risk_factors = {
            "browser_validation": {
                "enabled": True,
                "user_agent_legitimate": ua_validation["is_legitimate"],
                "browser_environment_valid": env_validation["is_real_browser"],
                "overall_risk_level": "REVIEW" if (
                    ua_validation["risk_level"] == "REVIEW" or
                    env_validation["risk_level"] == "REVIEW"
                ) else "ALLOW"
            }
        }

        # Merge specific risk factors
        risk_factors.update(ua_validation["risk_factors"])
        risk_factors.update(env_validation["risk_factors"])

        return risk_factors

    @staticmethod
    def add_custom_automation_pattern(pattern: str) -> bool:
        """Add a custom automation detection pattern"""
        try:
            re.compile(pattern)  # Validate regex
            if pattern not in BrowserValidationService.AUTOMATION_PATTERNS:
                BrowserValidationService.AUTOMATION_PATTERNS.append(pattern)
                return True
            return False
        except re.error:
            return False

    @staticmethod
    def remove_automation_pattern(pattern: str) -> bool:
        """Remove an automation detection pattern"""
        try:
            BrowserValidationService.AUTOMATION_PATTERNS.remove(pattern)
            return True
        except ValueError:
            return False