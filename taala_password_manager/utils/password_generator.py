"""
Secure password generation utilities for Taala Password Manager

Provides cryptographically secure password generation with customizable
character sets and complexity requirements following security best practices.

Features:
- Cryptographically secure randomness (not pseudo-random)
- Customizable character sets and length
- Built-in complexity validation
- Multiple generation strategies
"""

import secrets
import string
from typing import List, Set, Optional
from enum import Enum


class PasswordComplexity(Enum):
    """Password complexity levels with different character requirements."""
    SIMPLE = "simple"      # Letters and numbers only
    MODERATE = "moderate"  # Letters, numbers, and basic symbols
    STRONG = "strong"      # All printable ASCII characters
    CUSTOM = "custom"      # User-defined character set


class PasswordGenerator:
    """
    Generates cryptographically secure passwords with customizable complexity.

    Uses Python's secrets module for cryptographically secure random generation,
    which is suitable for security-sensitive applications like password generation.

    Features:
    - Multiple complexity levels
    - Custom character set support
    - Ensures minimum character type requirements
    - Validates generated passwords meet criteria
    """

    # Pre-defined character sets for different complexity levels
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    BASIC_SYMBOLS = "!@#$%^&*"
    EXTENDED_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def __init__(self):
        """Initialize the password generator."""
        self.complexity_sets = {
            PasswordComplexity.SIMPLE: {
                'chars': self.LOWERCASE + self.UPPERCASE + self.DIGITS,
                'required_types': [self.LOWERCASE, self.UPPERCASE, self.DIGITS]
            },
            PasswordComplexity.MODERATE: {
                'chars': self.LOWERCASE + self.UPPERCASE + self.DIGITS + self.BASIC_SYMBOLS,
                'required_types': [self.LOWERCASE, self.UPPERCASE, self.DIGITS, self.BASIC_SYMBOLS]
            },
            PasswordComplexity.STRONG: {
                'chars': self.LOWERCASE + self.UPPERCASE + self.DIGITS + self.EXTENDED_SYMBOLS,
                'required_types': [self.LOWERCASE, self.UPPERCASE, self.DIGITS, self.EXTENDED_SYMBOLS]
            }
        }

    def generate_password(
        self,
        length: int = 16,
        complexity: PasswordComplexity = PasswordComplexity.STRONG,
        custom_chars: Optional[str] = None,
        exclude_chars: Optional[str] = None
    ) -> str:
        """
        Generate a cryptographically secure password.

        Args:
            length: Desired password length (minimum 8, maximum 128)
            complexity: Password complexity level
            custom_chars: Custom character set (overrides complexity setting)
            exclude_chars: Characters to exclude from generation

        Returns:
            Generated password string

        Raises:
            ValueError: If parameters are invalid

        Security Notes:
            - Uses secrets.choice() for cryptographically secure randomness
            - Ensures at least one character from each required type
            - Re-generates if password doesn't meet complexity requirements
        """
        # Validate input parameters
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        if length > 128:
            raise ValueError("Password length cannot exceed 128 characters")

        # Determine character set and requirements
        if custom_chars:
            char_set = custom_chars
            required_types = []  # No type requirements for custom sets
        else:
            complexity_config = self.complexity_sets[complexity]
            char_set = complexity_config['chars']
            required_types = complexity_config['required_types']

        # Remove excluded characters
        if exclude_chars:
            char_set = ''.join(c for c in char_set if c not in exclude_chars)

        if not char_set:
            raise ValueError("Character set is empty after applying filters")

        # Generate password with complexity requirements
        max_attempts = 100  # Prevent infinite loops

        for _ in range(max_attempts):
            password = self._generate_random_password(char_set, length)

            # Check if password meets complexity requirements
            if self._meets_complexity_requirements(password, required_types):
                return password

        # If we couldn't generate a valid password, use forced method
        return self._generate_forced_complexity_password(char_set, length, required_types)

    def generate_memorable_password(
        self,
        word_count: int = 4,
        separator: str = "-",
        add_numbers: bool = True,
        capitalize: bool = True
    ) -> str:
        """
        Generate a memorable password using random words.

        Args:
            word_count: Number of words to include
            separator: Character to separate words
            add_numbers: Whether to add random numbers
            capitalize: Whether to capitalize first letter of each word

        Returns:
            Memorable password string

        Note:
            This uses a simplified word list for demonstration.
            In production, you'd use a larger dictionary like EFF's word list.
        """
        # Simple word list for demonstration (in practice, use EFF diceware list)
        words = [
            "apple", "bridge", "cloud", "dragon", "eagle", "forest", "galaxy", "house",
            "island", "jungle", "kingdom", "lighthouse", "mountain", "notebook", "ocean",
            "palace", "queen", "rainbow", "sunset", "tower", "umbrella", "village",
            "whisper", "xenon", "yellow", "zebra", "anchor", "butterfly", "castle",
            "diamond", "elephant", "flame", "garden", "horizon", "iceberg", "jasmine"
        ]

        # Select random words
        selected_words = [secrets.choice(words) for _ in range(word_count)]

        # Apply capitalization
        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]

        # Join with separator
        password = separator.join(selected_words)

        # Add random numbers if requested
        if add_numbers:
            number_suffix = str(secrets.randbelow(1000)).zfill(2)
            password += separator + number_suffix

        return password

    def generate_pin(self, length: int = 6) -> str:
        """
        Generate a numeric PIN.

        Args:
            length: PIN length (typically 4-8 digits)

        Returns:
            Numeric PIN string
        """
        if length < 4 or length > 8:
            raise ValueError("PIN length must be between 4 and 8 digits")

        # Generate PIN ensuring no leading zeros
        first_digit = secrets.choice("123456789")
        remaining_digits = ''.join(secrets.choice(self.DIGITS) for _ in range(length - 1))

        return first_digit + remaining_digits

    def generate_multiple_passwords(
        self,
        count: int,
        length: int = 16,
        complexity: PasswordComplexity = PasswordComplexity.STRONG
    ) -> List[str]:
        """
        Generate multiple passwords at once.

        Args:
            count: Number of passwords to generate
            length: Password length
            complexity: Password complexity level

        Returns:
            List of generated passwords
        """
        return [
            self.generate_password(length, complexity)
            for _ in range(count)
        ]

    def _generate_random_password(self, char_set: str, length: int) -> str:
        """
        Generate a purely random password from character set.

        Args:
            char_set: Available characters
            length: Password length

        Returns:
            Random password string
        """
        return ''.join(secrets.choice(char_set) for _ in range(length))

    def _meets_complexity_requirements(self, password: str, required_types: List[str]) -> bool:
        """
        Check if password meets complexity requirements.

        Args:
            password: Password to check
            required_types: List of required character sets

        Returns:
            True if password meets all requirements
        """
        if not required_types:
            return True  # No requirements for custom character sets

        for char_type in required_types:
            if not any(c in char_type for c in password):
                return False

        return True

    def _generate_forced_complexity_password(
        self,
        char_set: str,
        length: int,
        required_types: List[str]
    ) -> str:
        """
        Generate password ensuring complexity requirements are met.

        This method forces at least one character from each required type.

        Args:
            char_set: Available characters
            length: Password length
            required_types: Required character types

        Returns:
            Password meeting complexity requirements
        """
        if not required_types or length < len(required_types):
            # Fall back to random generation
            return self._generate_random_password(char_set, length)

        password_chars = []

        # Ensure at least one character from each required type
        for char_type in required_types:
            # Find intersection of char_type and char_set
            available_chars = [c for c in char_type if c in char_set]
            if available_chars:
                password_chars.append(secrets.choice(available_chars))

        # Fill remaining positions with random characters from full set
        remaining_length = length - len(password_chars)
        password_chars.extend(
            secrets.choice(char_set) for _ in range(remaining_length)
        )

        # Shuffle to avoid predictable patterns
        self._shuffle_list(password_chars)

        return ''.join(password_chars)

    def _shuffle_list(self, items: List) -> None:
        """
        Cryptographically secure list shuffling.

        Args:
            items: List to shuffle in-place
        """
        for i in range(len(items) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            items[i], items[j] = items[j], items[i]

    def get_entropy_estimate(
        self,
        password_length: int,
        character_set_size: int
    ) -> float:
        """
        Calculate estimated entropy of a password.

        Args:
            password_length: Length of the password
            character_set_size: Size of character set used

        Returns:
            Estimated entropy in bits

        Note:
            Entropy = log2(charset_size^length) = length * log2(charset_size)
        """
        import math
        return password_length * math.log2(character_set_size)

    def analyze_generated_password(self, password: str) -> dict:
        """
        Analyze a generated password for informational purposes.

        Args:
            password: Password to analyze

        Returns:
            Dictionary with analysis results
        """
        analysis = {
            "length": len(password),
            "has_lowercase": any(c in self.LOWERCASE for c in password),
            "has_uppercase": any(c in self.UPPERCASE for c in password),
            "has_digits": any(c in self.DIGITS for c in password),
            "has_symbols": any(c in (self.BASIC_SYMBOLS + self.EXTENDED_SYMBOLS) for c in password),
            "unique_chars": len(set(password)),
            "estimated_charset_size": self._estimate_charset_size(password)
        }

        analysis["entropy_estimate"] = self.get_entropy_estimate(
            analysis["length"],
            analysis["estimated_charset_size"]
        )

        return analysis

    def _estimate_charset_size(self, password: str) -> int:
        """
        Estimate the character set size based on password content.

        Args:
            password: Password to analyze

        Returns:
            Estimated character set size
        """
        size = 0

        if any(c in self.LOWERCASE for c in password):
            size += len(self.LOWERCASE)
        if any(c in self.UPPERCASE for c in password):
            size += len(self.UPPERCASE)
        if any(c in self.DIGITS for c in password):
            size += len(self.DIGITS)
        if any(c in (self.BASIC_SYMBOLS + self.EXTENDED_SYMBOLS) for c in password):
            # Estimate symbol count based on what we see
            symbols_used = set(c for c in password if c in (self.BASIC_SYMBOLS + self.EXTENDED_SYMBOLS))
            if symbols_used:
                # Assume full symbol set if any symbols are present
                size += len(self.EXTENDED_SYMBOLS)

        return max(size, len(set(password)))  # At least as many as unique chars


# Example usage and testing
if __name__ == "__main__":
    # Test password generation
    generator = PasswordGenerator()

    print("Testing Taala PasswordGenerator...")

    # Test different complexity levels
    complexities = [
        PasswordComplexity.SIMPLE,
        PasswordComplexity.MODERATE,
        PasswordComplexity.STRONG
    ]

    for complexity in complexities:
        password = generator.generate_password(16, complexity)
        analysis = generator.analyze_generated_password(password)
        print(f"{complexity.value.upper()} password: {password}")
        print(f"Length: {analysis['length']}, Entropy: {analysis['entropy_estimate']:.1f} bits")
        print(f"Lowercase: {analysis['has_lowercase']}, Uppercase: {analysis['has_uppercase']}")
        print(f"Digits: {analysis['has_digits']}, Symbols: {analysis['has_symbols']}")

    # Test memorable password
    memorable = generator.generate_memorable_password()
    print(f"Memorable password: {memorable}")

    # Test PIN generation
    pin = generator.generate_pin(6)
    print(f"Generated PIN: {pin}")

    print("PasswordGenerator test completed successfully!")
