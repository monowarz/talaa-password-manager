"""
Password strength analysis utilities for Taala Password Manager

Analyzes password strength based on multiple criteria including length,
character diversity, common patterns, and dictionary checks.

Follows OWASP password recommendations and provides educational feedback
to help users understand password security principles.
"""

import re
import math
from typing import Dict, List, Set, Tuple, Optional
from enum import Enum
from dataclasses import dataclass


class PasswordStrength(Enum):
    """Password strength levels with numeric scores."""
    VERY_WEAK = 1
    WEAK = 2
    MODERATE = 3
    STRONG = 4
    VERY_STRONG = 5


@dataclass
class StrengthAnalysis:
    """Container for password strength analysis results."""
    strength: PasswordStrength
    score: int
    max_score: int
    issues: List[str]
    recommendations: List[str]
    entropy: float
    estimated_crack_time: str


class PasswordStrengthChecker:
    """
    Comprehensive password strength analysis tool.

    Evaluates passwords based on multiple security criteria:
    - Length (OWASP recommends minimum 12 characters)
    - Character diversity (lowercase, uppercase, digits, symbols)
    - Common patterns and sequences
    - Dictionary words and common passwords
    - Entropy calculation
    - Crack time estimation

    Provides educational feedback to help users understand security principles.
    """

    # Common weak patterns to detect
    COMMON_PATTERNS = [
        r'(.){2,}',  # Repeated characters (aaa, 111)
        r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
        r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        r'(qwerty|asdfgh|zxcvbn)',  # Keyboard patterns
        r'(password|admin|login|user)',  # Common words (case insensitive)
    ]

    # Common weak passwords (abbreviated list for demonstration)
    COMMON_PASSWORDS = {
        "password", "123456", "password123", "admin", "qwerty", "letmein",
        "welcome", "monkey", "dragon", "pass", "master", "hello", "freedom",
        "whatever", "football", "jesus", "ninja", "mustang", "college", "home",
        "love", "summer", "internet", "service", "canada", "hello123", "root",
        "test", "guest", "123456789", "1234567890", "abc123", "password1",
        "qwerty123", "admin123", "root123", "test123", "user123", "pass123"
    }

    def __init__(self):
        """Initialize the password strength checker."""
        self.max_possible_score = 100

        # Character sets for analysis
        self.lowercase = set('abcdefghijklmnopqrstuvwxyz')
        self.uppercase = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        self.digits = set('0123456789')
        self.symbols = set('!@#$%^&*()_+-=[]{}|;:,.<>?')

        # Scoring weights
        self.scoring_weights = {
            'length': 25,           # Length is most important
            'character_types': 20,  # Character diversity
            'entropy': 20,          # Information entropy
            'patterns': 15,         # Avoid common patterns
            'dictionary': 10,       # Not in common passwords
            'bonus_factors': 10     # Additional security factors
        }

    def analyze_password(self, password: str) -> StrengthAnalysis:
        """
        Perform comprehensive password strength analysis.

        Args:
            password: Password string to analyze

        Returns:
            StrengthAnalysis object with detailed results
        """
        if not password:
            return StrengthAnalysis(
                strength=PasswordStrength.VERY_WEAK,
                score=0,
                max_score=self.max_possible_score,
                issues=["Password cannot be empty"],
                recommendations=["Please enter a password"],
                entropy=0.0,
                estimated_crack_time="Instant"
            )

        # Perform individual checks
        length_score, length_issues, length_recs = self._check_length(password)
        char_score, char_issues, char_recs = self._check_character_types(password)
        entropy_score, entropy_value = self._calculate_entropy_score(password)
        pattern_score, pattern_issues, pattern_recs = self._check_patterns(password)
        dict_score, dict_issues, dict_recs = self._check_dictionary(password)
        bonus_score, bonus_recs = self._calculate_bonus_factors(password)

        # Calculate total score
        total_score = (
            length_score + char_score + entropy_score + 
            pattern_score + dict_score + bonus_score
        )

        # Determine strength level
        strength = self._score_to_strength(total_score)

        # Collect all issues and recommendations
        all_issues = length_issues + char_issues + pattern_issues + dict_issues
        all_recommendations = length_recs + char_recs + pattern_recs + dict_recs + bonus_recs

        # Estimate crack time
        crack_time = self._estimate_crack_time(entropy_value, password)

        return StrengthAnalysis(
            strength=strength,
            score=total_score,
            max_score=self.max_possible_score,
            issues=all_issues,
            recommendations=all_recommendations,
            entropy=entropy_value,
            estimated_crack_time=crack_time
        )

    def _check_length(self, password: str) -> Tuple[int, List[str], List[str]]:
        """Check password length and provide scoring."""
        length = len(password)
        max_score = self.scoring_weights['length']
        issues = []
        recommendations = []

        if length < 8:
            score = 0
            issues.append(f"Password too short ({length} chars)")
            recommendations.append("Use at least 8 characters (12+ recommended)")
        elif length < 12:
            score = int(max_score * 0.6)  # 60% score for 8-11 chars
            recommendations.append("Consider using 12+ characters for better security")
        elif length < 16:
            score = int(max_score * 0.8)  # 80% score for 12-15 chars
        elif length < 20:
            score = max_score  # Full score for 16-19 chars
        else:
            score = max_score
            # Bonus for very long passwords is handled in bonus_factors

        return score, issues, recommendations

    def _check_character_types(self, password: str) -> Tuple[int, List[str], List[str]]:
        """Check character type diversity."""
        max_score = self.scoring_weights['character_types']
        password_set = set(password)
        issues = []
        recommendations = []

        # Check for each character type
        has_lowercase = bool(password_set & self.lowercase)
        has_uppercase = bool(password_set & self.uppercase)
        has_digits = bool(password_set & self.digits)
        has_symbols = bool(password_set & self.symbols)

        char_types_count = sum([has_lowercase, has_uppercase, has_digits, has_symbols])

        # Score based on character type diversity
        if char_types_count == 1:
            score = 0
            issues.append("Uses only one type of character")
            recommendations.append("Mix uppercase, lowercase, numbers, and symbols")
        elif char_types_count == 2:
            score = int(max_score * 0.4)
            recommendations.append("Add numbers and/or symbols for better security")
        elif char_types_count == 3:
            score = int(max_score * 0.7)
            if not has_symbols:
                recommendations.append("Consider adding symbols (!@#$%^&*)")
        else:  # char_types_count == 4
            score = max_score

        # Add specific missing type recommendations
        missing_types = []
        if not has_lowercase:
            missing_types.append("lowercase letters")
        if not has_uppercase:
            missing_types.append("uppercase letters")
        if not has_digits:
            missing_types.append("numbers")
        if not has_symbols:
            missing_types.append("symbols")

        if missing_types:
            issues.append(f"Missing: {', '.join(missing_types)}")

        return score, issues, recommendations

    def _calculate_entropy_score(self, password: str) -> Tuple[int, float]:
        """Calculate password entropy and convert to score."""
        max_score = self.scoring_weights['entropy']

        # Calculate character set size
        password_set = set(password)
        charset_size = 0

        if password_set & self.lowercase:
            charset_size += 26
        if password_set & self.uppercase:
            charset_size += 26
        if password_set & self.digits:
            charset_size += 10
        if password_set & self.symbols:
            charset_size += len(self.symbols)

        # Calculate entropy: log2(charset_size^length)
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
        else:
            entropy = 0

        # Convert entropy to score (entropy of 60+ bits gets full score)
        if entropy < 20:
            score = 0
        elif entropy < 40:
            score = int(max_score * 0.4)
        elif entropy < 60:
            score = int(max_score * 0.7)
        else:
            score = max_score

        return score, entropy

    def _check_patterns(self, password: str) -> Tuple[int, List[str], List[str]]:
        """Check for common weak patterns."""
        max_score = self.scoring_weights['patterns']
        issues = []
        recommendations = []

        pattern_count = 0

        for pattern in self.COMMON_PATTERNS:
            if re.search(pattern, password, re.IGNORECASE):
                pattern_count += 1

        # Check for dates (simple check for 4-digit years)
        if re.search(r'(19|20)\d{2}', password):
            pattern_count += 1
            issues.append("Contains what appears to be a year")

        # Check for repeated sequences
        if self._has_repeated_sequences(password):
            pattern_count += 1
            issues.append("Contains repeated character sequences")

        # Score based on pattern count
        if pattern_count == 0:
            score = max_score
        elif pattern_count == 1:
            score = int(max_score * 0.7)
            recommendations.append("Avoid predictable patterns")
        elif pattern_count == 2:
            score = int(max_score * 0.4)
            issues.append("Multiple predictable patterns detected")
            recommendations.append("Use more random character combinations")
        else:
            score = 0
            issues.append("Many predictable patterns detected")
            recommendations.append("Avoid keyboard patterns, sequences, and repetition")

        return score, issues, recommendations

    def _check_dictionary(self, password: str) -> Tuple[int, List[str], List[str]]:
        """Check against common password dictionary."""
        max_score = self.scoring_weights['dictionary']
        issues = []
        recommendations = []

        password_lower = password.lower()

        # Check exact match
        if password_lower in self.COMMON_PASSWORDS:
            score = 0
            issues.append("Password is in common password list")
            recommendations.append("Use a unique password not found in dictionaries")
            return score, issues, recommendations

        # Check for common passwords as substrings
        common_found = []
        for common_pwd in self.COMMON_PASSWORDS:
            if len(common_pwd) >= 4 and common_pwd in password_lower:
                common_found.append(common_pwd)

        if common_found:
            score = int(max_score * 0.3)
            issues.append(f"Contains common password elements: {', '.join(common_found[:3])}")
            recommendations.append("Avoid using common words as password base")
        else:
            score = max_score

        return score, issues, recommendations

    def _calculate_bonus_factors(self, password: str) -> Tuple[int, List[str]]:
        """Calculate bonus points for additional security factors."""
        max_score = self.scoring_weights['bonus_factors']
        bonus = 0
        recommendations = []

        # Bonus for very long passwords
        if len(password) >= 20:
            bonus += max_score * 0.3

        # Bonus for high character diversity
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.8:  # 80%+ unique characters
            bonus += max_score * 0.3

        # Bonus for avoiding all common patterns
        if not any(re.search(pattern, password, re.IGNORECASE) for pattern in self.COMMON_PATTERNS):
            bonus += max_score * 0.4

        # Ensure bonus doesn't exceed max
        bonus = min(bonus, max_score)

        if bonus < max_score:
            recommendations.append("Consider longer passwords with more unique characters")

        return int(bonus), recommendations

    def _has_repeated_sequences(self, password: str) -> bool:
        """Check for repeated sequences of 2+ characters."""
        for i in range(len(password) - 3):
            for seq_len in range(2, min(5, len(password) - i)):
                sequence = password[i:i + seq_len]
                # Check if this sequence appears again
                if password.count(sequence) > 1:
                    return True
        return False

    def _score_to_strength(self, score: int) -> PasswordStrength:
        """Convert numeric score to strength enum."""
        if score < 20:
            return PasswordStrength.VERY_WEAK
        elif score < 40:
            return PasswordStrength.WEAK
        elif score < 60:
            return PasswordStrength.MODERATE
        elif score < 80:
            return PasswordStrength.STRONG
        else:
            return PasswordStrength.VERY_STRONG

    def _estimate_crack_time(self, entropy: float, password: str) -> str:
        """
        Estimate time to crack password using brute force.

        Args:
            entropy: Password entropy in bits
            password: The password string

        Returns:
            Human-readable time estimate
        """
        if entropy == 0:
            return "Instant"

        # Assume 1 billion guesses per second (modern hardware)
        guesses_per_second = 1_000_000_000

        # Total possible combinations is 2^entropy
        # On average, need to try half of all combinations
        total_combinations = 2 ** entropy
        average_attempts = total_combinations / 2

        seconds = average_attempts / guesses_per_second

        # Convert to human readable format
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:  # 1 year
            return f"{seconds/86400:.0f} days"
        elif seconds < 3153600000:  # 100 years
            return f"{seconds/31536000:.0f} years"
        else:
            return "Centuries or more"

    def get_strength_description(self, strength: PasswordStrength) -> str:
        """Get descriptive text for strength level."""
        descriptions = {
            PasswordStrength.VERY_WEAK: "Very Weak - Unacceptable for any use",
            PasswordStrength.WEAK: "Weak - Vulnerable to attacks",
            PasswordStrength.MODERATE: "Moderate - Acceptable for low-security uses",
            PasswordStrength.STRONG: "Strong - Good for most applications",
            PasswordStrength.VERY_STRONG: "Very Strong - Excellent security"
        }
        return descriptions[strength]

    def suggest_improvements(self, password: str) -> List[str]:
        """Provide specific suggestions for improving a password."""
        analysis = self.analyze_password(password)
        suggestions = []

        # Combine issues and recommendations into actionable suggestions
        if len(password) < 12:
            suggestions.append(f"Increase length to at least 12 characters (currently {len(password)})")

        password_set = set(password)
        missing_types = []

        if not (password_set & self.lowercase):
            missing_types.append("lowercase letters")
        if not (password_set & self.uppercase):
            missing_types.append("UPPERCASE letters")
        if not (password_set & self.digits):
            missing_types.append("numbers")
        if not (password_set & self.symbols):
            missing_types.append("symbols (!@#$%^&*)")

        if missing_types:
            suggestions.append(f"Add {' and '.join(missing_types)}")

        if analysis.entropy < 50:
            suggestions.append("Increase randomness - avoid predictable patterns")

        if any(re.search(pattern, password, re.IGNORECASE) for pattern in self.COMMON_PATTERNS):
            suggestions.append("Remove keyboard patterns, sequences, or repeated characters")

        return suggestions


# Example usage and testing
if __name__ == "__main__":
    # Test password strength checker
    checker = PasswordStrengthChecker()

    print("Testing Taala PasswordStrengthChecker...")

    # Test passwords of varying strength
    test_passwords = [
        "123456",
        "password",
        "Password123",
        "P@ssw0rd123",
        "MyComplexP@ssw0rd2023!",
        "correct-horse-battery-staple",
        "Tr0ub4dor&3",
        "tr0ub4dor&3",  # Similar but lowercase
        "aB3$fG7*kL9#mN2@pQ5&rS8!",
    ]

    for password in test_passwords:
        analysis = checker.analyze_password(password)
        print(f"Password: '{password}'")
        print(f"Strength: {analysis.strength.name} ({analysis.score}/{analysis.max_score})")
        print(f"Entropy: {analysis.entropy:.1f} bits")
        print(f"Estimated crack time: {analysis.estimated_crack_time}")

        if analysis.issues:
            print(f"Issues: {'; '.join(analysis.issues[:2])}")  # Show first 2 issues

        if analysis.recommendations:
            print(f"Suggestions: {'; '.join(analysis.recommendations[:2])}")  # Show first 2 recommendations

    print("PasswordStrengthChecker test completed successfully!")
