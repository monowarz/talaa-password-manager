"""
Command Line Interface for Taala Password Manager

Provides a comprehensive command-line interface for all password manager
operations including initialization, password management, generation,
and analysis features.
"""

import argparse
import getpass
import sys
import os
import json
from typing import Optional
try:
    import colorama
    from colorama import Fore, Style, Back
    colorama.init()
    HAS_COLOR = True
except ImportError:
    # Fallback if colorama not available
    class Fore:
        RED = YELLOW = GREEN = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    HAS_COLOR = False

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from taala_password_manager.core.password_manager import PasswordManager
    from taala_password_manager.utils.password_generator import PasswordComplexity
    from taala_password_manager.utils.password_strength import PasswordStrength
except ImportError:
    # Fallback imports for when modules aren't properly organized yet
    print("⚠️  Import Error: Please ensure all modules are in the correct directories.")
    print("Run the setup script first or check your file organization.")
    sys.exit(1)


class CLIColors:
    """Color constants for CLI output."""
    ERROR = Fore.RED + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    INFO = Fore.CYAN
    PROMPT = Fore.MAGENTA + Style.BRIGHT
    HEADER = Fore.BLUE + Style.BRIGHT
    RESET = Style.RESET_ALL


class TaalaPasswordManagerCLI:
    """Command Line Interface for Taala Password Manager."""

    def __init__(self):
        """Initialize CLI with password manager instance."""
        self.pm = PasswordManager()
        self.colors = CLIColors()

    def print_colored(self, message: str, color: str = "", end: str = "\n"):
        """Print colored message to console."""
        print(f"{color}{message}{self.colors.RESET}", end=end)

    def print_header(self, title: str):
        """Print formatted header."""
        print()
        self.print_colored("=" * 60, self.colors.HEADER)
        self.print_colored(f" {title}", self.colors.HEADER + Style.BRIGHT)
        self.print_colored("=" * 60, self.colors.HEADER)
        print()

    def print_error(self, message: str):
        """Print error message."""
        self.print_colored(f"❌ Error: {message}", self.colors.ERROR)

    def print_success(self, message: str):
        """Print success message."""
        self.print_colored(f"✅ {message}", self.colors.SUCCESS)

    def print_warning(self, message: str):
        """Print warning message."""
        self.print_colored(f"⚠️  Warning: {message}", self.colors.WARNING)

    def print_info(self, message: str):
        """Print info message."""
        self.print_colored(f"ℹ️  {message}", self.colors.INFO)

    def secure_input(self, prompt: str) -> str:
        """Get secure password input (hidden)."""
        self.print_colored(f"{prompt}: ", self.colors.PROMPT, end="")
        return getpass.getpass("")

    def regular_input(self, prompt: str, default: str = "") -> str:
        """Get regular input with optional default."""
        if default:
            prompt_text = f"{prompt} [{default}]: "
        else:
            prompt_text = f"{prompt}: "

        self.print_colored(prompt_text, self.colors.PROMPT, end="")
        value = input().strip()
        return value if value else default

    def cmd_init(self, args):
        """Initialize password manager."""
        self.print_header("Initialize Taala Password Manager")

        if self.pm.is_initialized():
            self.print_error("Password manager is already initialized!")
            return

        self.print_info("Setting up your secure password vault...")
        print()
        self.print_colored("Your master password should be:", self.colors.INFO)
        self.print_colored("• At least 12 characters long", self.colors.INFO)
        self.print_colored("• Include uppercase, lowercase, numbers, and symbols", self.colors.INFO)
        self.print_colored("• Be unique and not used elsewhere", self.colors.INFO)
        self.print_colored("• Be memorable but not predictable", self.colors.INFO)
        print()

        # Get master password
        master_password = self.secure_input("Enter master password")

        if not master_password:
            self.print_error("Master password cannot be empty")
            return

        # Confirm master password
        confirm_password = self.secure_input("Confirm master password")

        if master_password != confirm_password:
            self.print_error("Passwords do not match!")
            return

        # Initialize password manager
        success, error = self.pm.initialize(master_password)

        if success:
            self.print_success("Password manager initialized successfully!")
            self.print_info("You can now add passwords using the 'add' command")
        else:
            self.print_error(error)

    def cmd_add(self, args):
        """Add new password entry."""
        self.print_header("Add New Password Entry")

        # Unlock if needed
        if not self._ensure_unlocked():
            return

        # Get entry details
        if hasattr(args, 'site') and args.site:
            site = args.site
        else:
            site = self.regular_input("Website/Service")

        if not site:
            self.print_error("Site is required")
            return

        if hasattr(args, 'username') and args.username:
            username = args.username
        else:
            username = self.regular_input("Username/Email")

        if not username:
            self.print_error("Username is required")
            return

        # Get password
        if hasattr(args, 'generate') and args.generate:
            # Generate password
            length = getattr(args, 'length', 16) or 16
            complexity_map = {
                'simple': PasswordComplexity.SIMPLE,
                'moderate': PasswordComplexity.MODERATE,
                'strong': PasswordComplexity.STRONG
            }
            complexity = complexity_map.get(getattr(args, 'complexity', 'strong'), PasswordComplexity.STRONG)

            password = self.pm.generate_password(length, complexity)
            self.print_info(f"Generated password: {password}")

        elif hasattr(args, 'password') and args.password:
            password = args.password
        else:
            password = self.secure_input("Password (or press Enter to generate)")
            if not password:
                # Generate password
                password = self.pm.generate_password(16, PasswordComplexity.STRONG)
                self.print_info(f"Generated password: {password}")

        # Get notes
        notes = getattr(args, 'notes', '') or self.regular_input("Notes (optional)")

        # Add entry
        success, error = self.pm.add_entry(site, username, password, notes)

        if success:
            self.print_success(f"Added password for {site}")
        else:
            self.print_error(error)

    def cmd_get(self, args):
        """Retrieve password entry."""
        self.print_header("Retrieve Password")

        # Unlock if needed
        if not self._ensure_unlocked():
            return

        site = args.site if hasattr(args, 'site') else self.regular_input("Website/Service")
        username = getattr(args, 'username', None)

        if not site:
            self.print_error("Site is required")
            return

        # Get entry
        success, entry, error = self.pm.get_entry(site, username)

        if success:
            print()
            self.print_colored(f"🌐 Site: {entry.site}", self.colors.INFO)
            self.print_colored(f"👤 Username: {entry.username}", self.colors.INFO)
            self.print_colored(f"🔑 Password: {entry.password}", self.colors.SUCCESS)

            if entry.notes:
                self.print_colored(f"📝 Notes: {entry.notes}", self.colors.INFO)

            self.print_colored(f"📅 Created: {entry.created_at[:19]}", self.colors.INFO)
        else:
            self.print_error(error)

    def cmd_list(self, args):
        """List all password entries."""
        self.print_header("Password Entries")

        # Unlock if needed
        if not self._ensure_unlocked():
            return

        filter_term = getattr(args, 'filter', None)
        entries = self.pm.list_entries(filter_term)

        if not entries:
            self.print_info("No password entries found.")
            return

        # Display entries
        print(f"{'Site':<25} {'Username':<30} {'Created':<12} {'Notes':<5}")
        print("-" * 75)

        for entry in entries:
            notes_indicator = "📝" if entry['has_notes'] else "  "
            created_date = entry['created_at'][:10]  # Just the date part

            print(f"{entry['site']:<25} {entry['username']:<30} {created_date:<12} {notes_indicator:<5}")

        print()
        self.print_info(f"Total entries: {len(entries)}")

    def cmd_generate(self, args):
        """Generate password."""
        self.print_header("Generate Secure Password")

        length = getattr(args, 'length', 16)
        complexity_map = {
            'simple': PasswordComplexity.SIMPLE,
            'moderate': PasswordComplexity.MODERATE,
            'strong': PasswordComplexity.STRONG
        }
        complexity = complexity_map.get(getattr(args, 'complexity', 'strong'), PasswordComplexity.STRONG)

        count = getattr(args, 'count', 1)

        if count > 1:
            passwords = self.pm.password_generator.generate_multiple_passwords(
                count, length, complexity
            )

            self.print_info(f"Generated {count} passwords:")
            for i, password in enumerate(passwords, 1):
                self.print_colored(f"{i:2d}. {password}", self.colors.SUCCESS)
        else:
            password = self.pm.generate_password(length, complexity)
            self.print_colored(f"Generated password: {password}", self.colors.SUCCESS)

    def cmd_strength(self, args):
        """Analyze password strength."""
        self.print_header("Password Strength Analysis")

        if hasattr(args, 'password') and args.password:
            password = args.password
        else:
            password = self.secure_input("Enter password to analyze")

        if not password:
            self.print_error("Password is required")
            return

        # Analyze password
        analysis = self.pm.check_password_strength(password)

        # Display results
        print()
        strength_color = self._get_strength_color(analysis['strength'])
        self.print_colored(f"💪 Strength: {analysis['strength']}", strength_color)
        self.print_colored(f"📊 Score: {analysis['score']}/{analysis['max_score']}", self.colors.INFO)
        self.print_colored(f"🔢 Entropy: {analysis['entropy']:.1f} bits", self.colors.INFO)
        self.print_colored(f"⏱️  Estimated crack time: {analysis['crack_time']}", self.colors.INFO)

        if analysis['issues']:
            print()
            self.print_colored("❌ Issues found:", self.colors.WARNING)
            for issue in analysis['issues']:
                self.print_colored(f"  • {issue}", self.colors.WARNING)

        if analysis['recommendations']:
            print()
            self.print_colored("💡 Recommendations:", self.colors.INFO)
            for rec in analysis['recommendations']:
                self.print_colored(f"  • {rec}", self.colors.INFO)

    def cmd_stats(self, args):
        """Show password manager statistics."""
        self.print_header("Password Manager Statistics")

        # Unlock if needed
        if not self._ensure_unlocked():
            return

        stats = self.pm.get_statistics()

        if 'error' in stats:
            self.print_error(stats['error'])
            return

        # Display statistics
        self.print_colored(f"📊 Total entries: {stats['total_entries']}", self.colors.INFO)
        self.print_colored(f"🌐 Unique sites: {stats['unique_sites']}", self.colors.INFO)
        self.print_colored(f"📝 Entries with notes: {stats['entries_with_notes']}", self.colors.INFO)

        if stats['weak_passwords'] > 0:
            self.print_colored(f"⚠️  Weak passwords: {stats['weak_passwords']}", self.colors.WARNING)
        else:
            self.print_colored("💪 Weak passwords: 0", self.colors.SUCCESS)

    def _ensure_unlocked(self) -> bool:
        """Ensure password manager is unlocked."""
        if not self.pm.is_initialized():
            self.print_error("Password manager not initialized. Run 'init' first.")
            return False

        if not self.pm._is_unlocked:
            master_password = self.secure_input("Enter master password")
            success, error = self.pm.unlock(master_password)

            if not success:
                self.print_error(error)
                return False

        return True

    def _get_strength_color(self, strength: str) -> str:
        """Get color for password strength."""
        strength_colors = {
            'VERY_WEAK': self.colors.ERROR,
            'WEAK': self.colors.WARNING,
            'MODERATE': Fore.YELLOW,
            'STRONG': self.colors.SUCCESS,
            'VERY_STRONG': self.colors.SUCCESS + Style.BRIGHT
        }
        return strength_colors.get(strength, self.colors.INFO)


def create_parser():
    """Create argument parser for CLI."""
    parser = argparse.ArgumentParser(
        prog='taala',
        description='Taala Password Manager - A lightweight, educational password manager'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Initialize command
    init_parser = subparsers.add_parser('init', help='Initialize password manager')

    # Add password command
    add_parser = subparsers.add_parser('add', help='Add new password entry')
    add_parser.add_argument('--site', '-s', help='Website/service domain')
    add_parser.add_argument('--username', '-u', help='Username or email')
    add_parser.add_argument('--password', '-p', help='Password for the account')
    add_parser.add_argument('--notes', '-n', help='Optional notes')
    add_parser.add_argument('--generate', '-g', action='store_true', help='Generate password automatically')
    add_parser.add_argument('--length', '-l', type=int, default=16, help='Generated password length (default: 16)')
    add_parser.add_argument('--complexity', '-c', choices=['simple', 'moderate', 'strong'], 
                          default='strong', help='Password complexity (default: strong)')

    # Get password command
    get_parser = subparsers.add_parser('get', help='Retrieve password entry')
    get_parser.add_argument('site', help='Website/service domain')
    get_parser.add_argument('--username', '-u', help='Username (optional)')

    # List passwords command
    list_parser = subparsers.add_parser('list', help='List all password entries')
    list_parser.add_argument('--filter', '-f', help='Filter entries by site name')

    # Generate password command
    gen_parser = subparsers.add_parser('generate', help='Generate secure password')
    gen_parser.add_argument('--length', '-l', type=int, default=16, help='Password length (default: 16)')
    gen_parser.add_argument('--complexity', '-c', choices=['simple', 'moderate', 'strong'], 
                          default='strong', help='Password complexity (default: strong)')
    gen_parser.add_argument('--count', type=int, default=1, help='Number of passwords to generate')

    # Password strength command
    strength_parser = subparsers.add_parser('strength', help='Analyze password strength')
    strength_parser.add_argument('--password', '-p', help='Password to analyze (will prompt if not provided)')

    # Statistics command
    stats_parser = subparsers.add_parser('stats', help='Show password manager statistics')

    return parser


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Create CLI instance
    cli = TaalaPasswordManagerCLI()

    # Show banner
    cli.print_colored("🔒 Taala Password Manager v1.0", cli.colors.HEADER + Style.BRIGHT)
    cli.print_colored("A lightweight, educational password manager\n", cli.colors.INFO)

    # Handle commands
    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'init':
            cli.cmd_init(args)
        elif args.command == 'add':
            cli.cmd_add(args)
        elif args.command == 'get':
            cli.cmd_get(args)
        elif args.command == 'list':
            cli.cmd_list(args)
        elif args.command == 'generate':
            cli.cmd_generate(args)
        elif args.command == 'strength':
            cli.cmd_strength(args)
        elif args.command == 'stats':
            cli.cmd_stats(args)
        else:
            cli.print_error(f"Unknown command: {args.command}")
            parser.print_help()

    except KeyboardInterrupt:
        cli.print_info("\nOperation cancelled by user.")
    except Exception as e:
        cli.print_error(f"Unexpected error: {e}")
        if os.getenv('DEBUG'):
            import traceback
            traceback.print_exc()
    finally:
        # Always lock the password manager when exiting
        cli.pm.lock()


if __name__ == '__main__':
    main()
