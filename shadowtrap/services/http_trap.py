"""HTTP Honeypot — serves fake login pages and captures credentials/payloads."""

import asyncio
import json
from urllib.parse import parse_qs, urlparse
from shadowtrap.services.base import BaseHoneypot


FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>Admin Panel - Login</title>
<style>
body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex;
       justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
.login-box { background: white; padding: 40px; border-radius: 8px;
             box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }
h2 { text-align: center; color: #333; margin-bottom: 20px; }
input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd;
        border-radius: 4px; box-sizing: border-box; }
button { width: 100%; padding: 10px; background: #007bff; color: white;
         border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
button:hover { background: #0056b3; }
.footer { text-align: center; margin-top: 15px; font-size: 12px; color: #888; }
</style></head>
<body><div class="login-box">
<h2>System Login</h2>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
<div class="footer">Authorized access only</div>
</div></body></html>"""


class HTTPHoneypot(BaseHoneypot):
    """HTTP honeypot that serves fake pages and captures requests."""

    SERVICE_NAME = "http"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.server_header = self.config.get("server_header", "Apache/2.4.58 (Ubuntu)")
        self.capture_post = self.config.get("capture_post_data", True)
        self.capture_headers = self.config.get("capture_headers", True)

    async def start(self) -> asyncio.AbstractServer:
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port
        )
        return server

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        session_id = self.new_session()

        if not self.check_rate_limit(src_ip):
            writer.close()
            return

        try:
            # Read the HTTP request
            request_data = await asyncio.wait_for(reader.read(8192), timeout=30)
            request_text = request_data.decode(errors="replace")

            if not request_text:
                return

            lines = request_text.split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split(" ")
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"

            # Parse headers
            headers = {}
            body = ""
            header_done = False
            for line in lines[1:]:
                if not header_done and line == "":
                    header_done = True
                    continue
                if header_done:
                    body += line
                elif ": " in line:
                    key, val = line.split(": ", 1)
                    headers[key.lower()] = val

            self.log_event(
                "http_request",
                src_ip=src_ip, src_port=src_port,
                dst_port=self.port, session_id=session_id,
                payload=json.dumps({
                    "method": method,
                    "path": path,
                    "user_agent": headers.get("user-agent", ""),
                    "headers": headers if self.capture_headers else {},
                }),
            )

            # Handle POST — capture credentials
            if method == "POST" and self.capture_post and body:
                form_data = parse_qs(body)
                username = form_data.get("username", [""])[0]
                password = form_data.get("password", [""])[0]

                if username or password:
                    self.log_event(
                        "login_attempt",
                        src_ip=src_ip, src_port=src_port,
                        dst_port=self.port, session_id=session_id,
                        username=username, password=password,
                    )

            # Send response
            response_body = FAKE_LOGIN_PAGE
            status = "200 OK"

            if path in ("/robots.txt",):
                response_body = "User-agent: *\nDisallow: /admin\nDisallow: /config"
            elif path == "/favicon.ico":
                status = "404 Not Found"
                response_body = ""

            http_response = (
                f"HTTP/1.1 {status}\r\n"
                f"Server: {self.server_header}\r\n"
                f"Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                f"Connection: close\r\n"
                f"X-Powered-By: PHP/8.2.12\r\n"
                f"\r\n"
                f"{response_body}"
            )

            writer.write(http_response.encode())
            await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
