import pytest
from unittest.mock import Mock, AsyncMock
from datetime import datetime
from typing import Dict, Any

from app.services.risk_engine import RiskEngine
from app.schemas.identity import IdentityVerificationRequest, SessionData, Context
from app.schemas.common import RiskLevel, ActionType


class TestWeightedScoring:
    """Test suite for weighted scoring functionality in the Risk Engine"""

    def setup_method(self):
        """Set up test fixtures"""
        self.risk_engine = RiskEngine()

    def test_calculate_weighted_score_basic(self):
        """Test basic weighted score calculation"""
        factor_scores = {
            "ip_reputation": {"score": 80.0, "weight": 0.6},
            "device_trust": {"score": 60.0, "weight": 0.2},
            "travel_feasibility": {"score": 90.0, "weight": 0.15},
            "temporal_behavior": {"score": 70.0, "weight": 0.05}
        }

        result = self.risk_engine._calculate_weighted_score(factor_scores, True)

        # Expected: (80*0.6 + 60*0.2 + 90*0.15 + 70*0.05) / (0.6+0.2+0.15+0.05)
        # = (48 + 12 + 13.5 + 3.5) / 1.0 = 77
        assert result == 77

    def test_calculate_weighted_score_empty_factors(self):
        """Test weighted score calculation with empty factors"""
        factor_scores = {}
        result = self.risk_engine._calculate_weighted_score(factor_scores, True)
        assert result == 50  # Fallback score

    def test_calculate_weighted_score_zero_weights(self):
        """Test weighted score calculation with zero weights"""
        factor_scores = {
            "ip_reputation": {"score": 80.0, "weight": 0.0},
            "device_trust": {"score": 60.0, "weight": 0.0}
        }
        result = self.risk_engine._calculate_weighted_score(factor_scores, True)
        assert result == 50  # Fallback score when no valid weights

    def test_calculate_weighted_score_invalid_scores(self):
        """Test weighted score calculation with invalid scores"""
        factor_scores = {
            "ip_reputation": {"score": 150.0, "weight": 0.6},  # Invalid score > 100
            "device_trust": {"score": -10.0, "weight": 0.2},   # Invalid score < 0
            "travel_feasibility": {"score": 80.0, "weight": 0.2}  # Valid
        }
        result = self.risk_engine._calculate_weighted_score(factor_scores, True)
        # Should only use travel_feasibility: 80 * 0.2 / 0.2 = 80
        assert result == 80

    def test_extract_factor_scores_ip_only(self):
        """Test factor score extraction with IP only"""
        ip_score = 85
        advanced_analysis = {"risk_factors": {}}

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "ip_reputation" in factor_scores
        assert factor_scores["ip_reputation"]["score"] == 85.0
        assert factor_scores["ip_reputation"]["weight"] == 0.6

    def test_extract_factor_scores_with_device_trust(self):
        """Test factor score extraction with device trust"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": True,
                    "device_age_days": 45
                }
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "device_trust" in factor_scores
        # Trusted device (80) + age bonus (10) = 90
        assert factor_scores["device_trust"]["score"] == 90.0
        assert factor_scores["device_trust"]["weight"] == 0.2

    def test_extract_factor_scores_new_untrusted_device(self):
        """Test factor score extraction with new untrusted device"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": False,
                    "device_age_days": 2
                }
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "device_trust" in factor_scores
        # Untrusted device = 40 (no age bonus for very new device)
        assert factor_scores["device_trust"]["score"] == 40.0

    def test_extract_factor_scores_with_travel_analysis(self):
        """Test factor score extraction with travel analysis"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "travel_analysis": {
                    "is_feasible": True
                }
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "travel_feasibility" in factor_scores
        assert factor_scores["travel_feasibility"]["score"] == 80.0
        assert factor_scores["travel_feasibility"]["weight"] == 0.15

    def test_extract_factor_scores_impossible_travel(self):
        """Test factor score extraction with impossible travel"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "travel_analysis": {
                    "is_feasible": False
                }
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "travel_feasibility" in factor_scores
        assert factor_scores["travel_feasibility"]["score"] == 10.0

    def test_extract_factor_scores_with_temporal_anomaly(self):
        """Test factor score extraction with temporal anomaly"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "temporal_anomaly": {
                    "score": 0.8  # High anomaly score
                }
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "temporal_behavior" in factor_scores
        # 100 - (0.8 * 100) = 20
        assert factor_scores["temporal_behavior"]["score"] == 20.0

    def test_extract_factor_scores_with_additional_factors(self):
        """Test factor score extraction with hardware and browser validation"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "hardware_validation": {"valid": True},
                "browser_validation": {"legitimate": True}
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        assert "hardware_validation" in factor_scores
        assert "browser_validation" in factor_scores

        # Check that weights sum properly
        total_weight = sum(f["weight"] for f in factor_scores.values())
        assert abs(total_weight - 1.0) < 0.01  # Should be close to 1.0

    def test_apply_penalty_adjustments(self):
        """Test penalty adjustment application"""
        base_score = 80
        penalty_scores = {
            "new_device_penalty": -15,
            "temporal_penalty": -10
        }

        result = self.risk_engine._apply_penalty_adjustments(base_score, penalty_scores)

        assert result == 55  # 80 - 15 - 10

    def test_apply_penalty_adjustments_bounds(self):
        """Test penalty adjustments respect bounds"""
        # Test lower bound
        base_score = 20
        penalty_scores = {"severe_penalty": -50}
        result = self.risk_engine._apply_penalty_adjustments(base_score, penalty_scores)
        assert result == 0  # Should not go below 0

        # Test upper bound
        base_score = 90
        bonus_scores = {"bonus": 20}
        result = self.risk_engine._apply_penalty_adjustments(base_score, bonus_scores)
        assert result == 100  # Should not go above 100

    def test_calculate_confidence_score_weighted_basic_mode(self):
        """Test weighted confidence score calculation in basic mode"""
        ip_score = 75
        advanced_analysis = {}

        result = self.risk_engine._calculate_confidence_score_weighted(
            ip_score, advanced_analysis, enable_advanced=False
        )

        assert result == 75  # Should return IP score unchanged

    def test_calculate_confidence_score_weighted_advanced_mode(self):
        """Test weighted confidence score calculation in advanced mode"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": True,
                    "device_age_days": 30
                }
            },
            "scores": {
                "new_device_penalty": -10
            }
        }

        result = self.risk_engine._calculate_confidence_score_weighted(
            ip_score, advanced_analysis, enable_advanced=True
        )

        # Should calculate weighted score then apply penalties
        assert isinstance(result, int)
        assert 0 <= result <= 100

    def test_weighted_scoring_scenario_high_trust(self):
        """Test weighted scoring scenario: High trust user"""
        ip_score = 90  # Good IP
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": True,
                    "device_age_days": 60
                },
                "travel_analysis": {
                    "is_feasible": True
                }
            },
            "scores": {}
        }

        result = self.risk_engine._calculate_confidence_score_weighted(
            ip_score, advanced_analysis, enable_advanced=True
        )

        # High confidence expected: Good IP (90*0.6) + Trusted device (90*0.2) + Feasible travel (80*0.15)
        # = 54 + 18 + 12 = 84
        assert result >= 80

    def test_weighted_scoring_scenario_medium_risk(self):
        """Test weighted scoring scenario: Medium risk user"""
        ip_score = 70  # Moderate IP
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": False,
                    "device_age_days": 5
                },
                "travel_analysis": {
                    "is_feasible": True
                }
            },
            "scores": {
                "new_device_penalty": -15
            }
        }

        result = self.risk_engine._calculate_confidence_score_weighted(
            ip_score, advanced_analysis, enable_advanced=True
        )

        # Should be in REVIEW range (30-70)
        assert 30 <= result <= 70

    def test_weighted_scoring_scenario_high_risk(self):
        """Test weighted scoring scenario: High risk user"""
        ip_score = 40  # Poor IP
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": False,
                    "device_age_days": 0
                },
                "travel_analysis": {
                    "is_feasible": False
                }
            },
            "scores": {
                "new_device_penalty": -15,
                "travel_violation": -100  # This would trigger DENY override
            }
        }

        result = self.risk_engine._calculate_confidence_score_weighted(
            ip_score, advanced_analysis, enable_advanced=True
        )

        # Should be in DENY range (< 30)
        assert result < 30

    def test_weight_consistency_across_methods(self):
        """Test that weights are consistent between calculation and risk factor creation"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {
                    "is_trusted": True,
                    "device_age_days": 30
                },
                "travel_analysis": {
                    "is_feasible": True
                }
            }
        }

        # Get factor scores used in calculation
        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        # Get risk factors for response
        risk_factors = self.risk_engine._create_comprehensive_risk_factors(
            {"country": "US", "proxy": "no", "risk": 20},
            ip_score,
            advanced_analysis["risk_factors"],
            enable_advanced=True
        )

        # Verify weights match
        for risk_factor in risk_factors:
            factor_name = risk_factor.factor
            if factor_name == "ip_reputation":
                assert risk_factor.weight == 0.6
            elif factor_name == "device_trust":
                assert risk_factor.weight == 0.2
                # Verify score calculation matches
                expected_score = factor_scores.get("device_trust", {}).get("score", 0)
                assert risk_factor.score == int(expected_score)
            elif factor_name == "travel_feasibility":
                assert risk_factor.weight == 0.15
                expected_score = factor_scores.get("travel_feasibility", {}).get("score", 0)
                assert risk_factor.score == int(expected_score)

    def test_normalized_weights_sum_to_one(self):
        """Test that factor weights approximately sum to 1.0"""
        ip_score = 80
        advanced_analysis = {
            "risk_factors": {
                "device_analysis": {"is_trusted": True, "device_age_days": 30},
                "travel_analysis": {"is_feasible": True},
                "temporal_anomaly": {"score": 0.3},
                "hardware_validation": {"valid": True},
                "browser_validation": {"legitimate": True}
            }
        }

        factor_scores = self.risk_engine._extract_factor_scores(ip_score, advanced_analysis)

        total_weight = sum(f["weight"] for f in factor_scores.values())

        # Should be very close to 1.0 (allowing small floating point differences)
        assert abs(total_weight - 1.0) < 0.01