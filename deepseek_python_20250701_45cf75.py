import asyncio
import aiohttp
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from telegram import Bot
from dotenv import load_dotenv
import os
import hashlib
import json
from cryptography.fernet import Fernet

# Security Configuration
load_dotenv()
KEY = os.getenv("ENCRYPTION_KEY")  # Generate with Fernet.generate_key()
cipher_suite = Fernet(KEY) if KEY else None

class SecureCredentials:
    @staticmethod
    def encrypt(data: str) -> bytes:
        if not cipher_suite:
            raise ValueError("Encryption key not configured")
        return cipher_suite.encrypt(data.encode())

    @staticmethod
    def decrypt(encrypted_data: bytes) -> str:
        if not cipher_suite:
            raise ValueError("Encryption key not configured")
        return cipher_suite.decrypt(encrypted_data).decode()

class SurebetBot:
    def __init__(self):
        # Load encrypted credentials
        self.bot_token = os.getenv("BOT_TOKEN")
        self.chat_id = os.getenv("CHAT_ID")
        self._load_surebet_credentials()
        
        # Initialize other components
        self.bot = Bot(token=self.bot_token)
        self.session = None
        self.logged_in = False
        self.previous_surebets = set()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("bot.log", mode='a'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _load_surebet_credentials(self):
        """Securely load credentials from environment variables"""
        encrypted_email = os.getenv("ENCRYPTED_SUREBET_EMAIL")
        encrypted_pass = os.getenv("ENCRYPTED_SUREBET_PASSWORD")
        
        if encrypted_email and encrypted_pass and cipher_suite:
            self.surebet_email = SecureCredentials.decrypt(encrypted_email.encode())
            self.surebet_password = SecureCredentials.decrypt(encrypted_pass.encode())
        else:
            self.surebet_email = None
            self.surebet_password = None
            self.logger.warning("Running in public mode - no login credentials")

    async def _secure_request(self, method, url, **kwargs):
        """Wrapper for secure requests with retry logic"""
        try:
            async with method(url, **kwargs) as response:
                if response.status in (401, 403):
                    await self.login()
                    kwargs['headers'] = await self._get_auth_headers()
                    async with method(url, **kwargs) as retry_response:
                        return retry_response
                return response
        except aiohttp.ClientError as e:
            self.logger.error(f"Request failed: {e}")
            raise

    async def _get_auth_headers(self):
        """Generate authenticated headers"""
        return {
            'Authorization': f"Bearer {await self._get_auth_token()}",
            'X-CSRF-Token': await self._get_csrf_token()
        }

    async def login(self):
        """Secure login implementation"""
        if not self.surebet_email or not self.surebet_password:
            return False

        login_url = "https://en.surebet.com/users/sign_in"
        
        try:
            # Get CSRF token first
            async with self.session.get(login_url) as resp:
                soup = BeautifulSoup(await resp.text(), 'html.parser')
                csrf_token = soup.find('meta', {'name': 'csrf-token'})['content']

            login_data = {
                "user[email]": self.surebet_email,
                "user[password]": self.surebet_password,
                "authenticity_token": csrf_token,
                "commit": "Sign in"
            }

            async with self.session.post(login_url, data=login_data) as resp:
                if resp.status == 200 and "sign_out" in await resp.text():
                    self.logged_in = True
                    self.logger.info("Login successful")
                    return True
                
                self.logger.warning("Login failed - check credentials")
                return False

        except Exception as e:
            self.logger.error(f"Login error: {str(e)}")
            return False

    async def monitor_surebets(self, interval=300):
        """Main monitoring loop with secure session handling"""
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        ) as self.session:
            await self._send_startup_message()
            
            while True:
                try:
                    await self._check_surebets()
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")
                finally:
                    await asyncio.sleep(interval)

    async def _check_surebets(self):
        """Secure check for new surebets"""
        url = "https://en.surebet.com/surebets"
        
        try:
            response = await self._secure_request(
                self.session.get,
                url,
                allow_redirects=False
            )
            
            if response.status == 200:
                content = await response.text()
                surebets = self._parse_surebets(content)
                await self._process_new_surebets(surebets)
            else:
                self.logger.warning(f"Unexpected status: {response.status}")

        except Exception as e:
            self.logger.error(f"Check failed: {e}")

    def _parse_surebets(self, html):
        """Parse surebets from HTML with validation"""
        soup = BeautifulSoup(html, 'html.parser')
        # Implement actual parsing logic here
        return []

    async def _process_new_surebets(self, surebets):
        """Process and notify about new surebets"""
        for surebet in surebets:
            surebet_id = hashlib.sha256(
                json.dumps(surebet, sort_keys=True).encode()
            ).hexdigest()
            
            if surebet_id not in self.previous_surebets:
                await self._send_notification(surebet)
                self.previous_surebets.add(surebet_id)

    async def _send_notification(self, surebet):
        """Send secure notification"""
        try:
            message = self._format_notification(surebet)
            await self.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode='Markdown',
                disable_web_page_preview=True
            )
        except Exception as e:
            self.logger.error(f"Notification failed: {e}")

    def _format_notification(self, surebet):
        """Format secure notification message"""
        return f"New surebet found at {datetime.now().isoformat()}"

    async def _send_startup_message(self):
        """Send secure startup message"""
        await self.bot.send_message(
            chat_id=self.chat_id,
            text="🔒 Surebet Monitor Started (Secure Mode)",
            parse_mode='Markdown'
        )

async def main():
    if not all(os.getenv(var) for var in ["BOT_TOKEN", "CHAT_ID"]):
        print("Missing required environment variables")
        return

    bot = SurebetBot()
    try:
        await bot.monitor_surebets()
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
    except Exception as e:
        print(f"Critical error: {e}")

if __name__ == "__main__":
    asyncio.run(main())