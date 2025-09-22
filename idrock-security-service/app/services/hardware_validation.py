from typing import Dict, Any, Optional


class HardwareValidationService:
    """Service for validating hardware specifications to detect real computers"""

    # Minimum requirements for real computer validation
    MIN_CPU_CORES = 2
    MIN_RAM_GB = 4

    @staticmethod
    def validate_hardware_specs(hardware_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate hardware specifications against minimum requirements.

        Args:
            hardware_info: Dictionary containing hardware data from client:
                {
                    "cpu_cores": int,
                    "ram_gb": float,
                    "screen_resolution": str,
                    "timezone": str,
                    "platform": str,
                    "language": str
                }

        Returns:
            Dict containing validation results:
            {
                "is_valid_hardware": bool,
                "risk_level": str,  # "ALLOW", "REVIEW"
                "validation_details": dict,
                "risk_factors": dict
            }
        """
        if not hardware_info:
            return {
                "is_valid_hardware": False,
                "risk_level": "REVIEW",
                "validation_details": {
                    "reason": "no_hardware_data",
                    "message": "No hardware information provided"
                },
                "risk_factors": {
                    "missing_hardware_info": {
                        "detected": True,
                        "severity": "medium",
                        "description": "Client did not provide hardware specifications"
                    }
                }
            }

        validation_results = {}
        risk_factors = {}
        issues = []

        # Validate CPU cores
        cpu_cores = hardware_info.get("cpu_cores")
        if cpu_cores is None:
            issues.append("Missing CPU core information")
            risk_factors["missing_cpu_info"] = {
                "detected": True,
                "severity": "medium",
                "description": "CPU core count not provided"
            }
        elif not isinstance(cpu_cores, int) or cpu_cores < HardwareValidationService.MIN_CPU_CORES:
            issues.append(f"Insufficient CPU cores: {cpu_cores} (minimum: {HardwareValidationService.MIN_CPU_CORES})")
            risk_factors["insufficient_cpu"] = {
                "detected": True,
                "severity": "high",
                "description": f"CPU cores ({cpu_cores}) below minimum requirement ({HardwareValidationService.MIN_CPU_CORES})"
            }
        else:
            validation_results["cpu_validation"] = {
                "cores": cpu_cores,
                "meets_minimum": True,
                "threshold": HardwareValidationService.MIN_CPU_CORES
            }

        # Validate RAM
        ram_gb = hardware_info.get("ram_gb")
        if ram_gb is None:
            issues.append("Missing RAM information")
            risk_factors["missing_ram_info"] = {
                "detected": True,
                "severity": "medium",
                "description": "RAM amount not provided"
            }
        elif not isinstance(ram_gb, (int, float)) or ram_gb < HardwareValidationService.MIN_RAM_GB:
            issues.append(f"Insufficient RAM: {ram_gb}GB (minimum: {HardwareValidationService.MIN_RAM_GB}GB)")
            risk_factors["insufficient_ram"] = {
                "detected": True,
                "severity": "high",
                "description": f"RAM ({ram_gb}GB) below minimum requirement ({HardwareValidationService.MIN_RAM_GB}GB)"
            }
        else:
            validation_results["ram_validation"] = {
                "ram_gb": ram_gb,
                "meets_minimum": True,
                "threshold": HardwareValidationService.MIN_RAM_GB
            }

        # Validate screen resolution (basic check for realistic values)
        screen_resolution = hardware_info.get("screen_resolution")
        if screen_resolution:
            resolution_valid = HardwareValidationService._validate_screen_resolution(screen_resolution)
            validation_results["screen_validation"] = {
                "resolution": screen_resolution,
                "is_valid": resolution_valid
            }
            if not resolution_valid:
                issues.append(f"Suspicious screen resolution: {screen_resolution}")
                risk_factors["suspicious_resolution"] = {
                    "detected": True,
                    "severity": "low",
                    "description": f"Unusual screen resolution reported: {screen_resolution}"
                }

        # Additional validations
        HardwareValidationService._validate_additional_specs(hardware_info, validation_results, risk_factors, issues)

        # Determine overall validation result
        has_critical_issues = any(
            factor.get("severity") == "high"
            for factor in risk_factors.values()
        )

        is_valid_hardware = len(issues) == 0
        risk_level = "REVIEW" if (has_critical_issues or not is_valid_hardware) else "ALLOW"

        return {
            "is_valid_hardware": is_valid_hardware,
            "risk_level": risk_level,
            "validation_details": {
                "issues": issues,
                "validations_passed": validation_results,
                "hardware_summary": {
                    "cpu_cores": cpu_cores,
                    "ram_gb": ram_gb,
                    "screen_resolution": screen_resolution,
                    "platform": hardware_info.get("platform"),
                    "timezone": hardware_info.get("timezone")
                }
            },
            "risk_factors": risk_factors
        }

    @staticmethod
    def _validate_screen_resolution(resolution: str) -> bool:
        """Validate screen resolution format and realistic values"""
        try:
            if 'x' not in resolution.lower():
                return False

            parts = resolution.lower().split('x')
            if len(parts) != 2:
                return False

            width = int(parts[0].strip())
            height = int(parts[1].strip())

            # Check for realistic resolution ranges
            # Minimum: 800x600, Maximum: 7680x4320 (8K)
            return (800 <= width <= 7680 and
                    600 <= height <= 4320 and
                    width > height)  # Width typically > height

        except (ValueError, AttributeError):
            return False

    @staticmethod
    def _validate_additional_specs(
        hardware_info: Dict[str, Any],
        validation_results: Dict[str, Any],
        risk_factors: Dict[str, Any],
        issues: list
    ):
        """Validate additional hardware specifications"""

        # Platform validation
        platform = hardware_info.get("platform")
        if platform:
            valid_platforms = ["Win32", "MacIntel", "Linux x86_64", "Linux i686"]
            if platform not in valid_platforms:
                risk_factors["unusual_platform"] = {
                    "detected": True,
                    "severity": "low",
                    "description": f"Unusual platform reported: {platform}"
                }

        # Timezone validation
        timezone = hardware_info.get("timezone")
        if timezone:
            # Basic timezone validation (should be offset in minutes)
            try:
                tz_offset = int(timezone)
                # Valid timezone range: -12 to +14 hours (-720 to +840 minutes)
                if not (-720 <= tz_offset <= 840):
                    risk_factors["invalid_timezone"] = {
                        "detected": True,
                        "severity": "low",
                        "description": f"Invalid timezone offset: {tz_offset} minutes"
                    }
            except (ValueError, TypeError):
                risk_factors["malformed_timezone"] = {
                    "detected": True,
                    "severity": "low",
                    "description": f"Malformed timezone data: {timezone}"
                }

        # Language validation
        language = hardware_info.get("language")
        if language and len(language) > 10:  # Basic length check
            risk_factors["suspicious_language"] = {
                "detected": True,
                "severity": "low",
                "description": f"Suspicious language string: {language[:20]}..."
            }

    @staticmethod
    def get_hardware_risk_factors(hardware_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get hardware-related risk factors for integration with risk engine.

        Returns risk factors that can be integrated into the main risk assessment.
        """
        validation_result = HardwareValidationService.validate_hardware_specs(hardware_info)

        risk_factors = {
            "hardware_validation": {
                "enabled": True,
                "is_valid_hardware": validation_result["is_valid_hardware"],
                "risk_level": validation_result["risk_level"],
                "validation_summary": validation_result["validation_details"]
            }
        }

        # Merge specific risk factors
        risk_factors.update(validation_result["risk_factors"])

        return risk_factors

    @staticmethod
    def update_minimum_requirements(min_cpu_cores: int, min_ram_gb: float) -> bool:
        """
        Update minimum hardware requirements.

        Args:
            min_cpu_cores: Minimum CPU cores required
            min_ram_gb: Minimum RAM in GB required

        Returns:
            bool: True if requirements were updated successfully
        """
        if min_cpu_cores <= 0 or min_ram_gb <= 0:
            return False

        HardwareValidationService.MIN_CPU_CORES = min_cpu_cores
        HardwareValidationService.MIN_RAM_GB = min_ram_gb
        return True

    @staticmethod
    def extract_hardware_from_user_agent(user_agent: str) -> Dict[str, Any]:
        """
        Extract basic hardware information from User-Agent string.

        This is a fallback method when JavaScript hardware detection is not available.
        """
        hardware_info = {}

        if not user_agent:
            return hardware_info

        user_agent_lower = user_agent.lower()

        # Detect platform
        if 'windows' in user_agent_lower:
            hardware_info['platform'] = 'Win32'
        elif 'macintosh' in user_agent_lower or 'mac os' in user_agent_lower:
            hardware_info['platform'] = 'MacIntel'
        elif 'linux' in user_agent_lower:
            if 'x86_64' in user_agent_lower:
                hardware_info['platform'] = 'Linux x86_64'
            else:
                hardware_info['platform'] = 'Linux i686'

        # This method provides limited information compared to JavaScript APIs
        # It's mainly used as a fallback for basic platform detection
        hardware_info['source'] = 'user_agent_fallback'
        hardware_info['limitations'] = 'Limited hardware detection via User-Agent'

        return hardware_info