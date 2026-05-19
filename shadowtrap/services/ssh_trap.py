"""SSH Honeypot — emulates an OpenSSH server to capture credentials and commands."""

import asyncio
import socket
from shadowtrap.services.base import BaseHoneypot


class SSHHoneypot(BaseHoneypot):
    """SSH honeypot that captures login attempts and post-auth commands."""

    SERVICE_NAME = "ssh"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.banner = self.config.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.max_auth = self.config.get("max_auth_attempts", 6)
        self.emulate_shell = self.config.get("emulate_shell", True)
        self.commands = {}
        for cmd_entry in self.config.get("recorded_commands", []):
            if isinstance(cmd_entry, dict):
                for cmd, response in cmd_entry.items():
                    self.commands[cmd] = response

    async def start(self) -> asyncio.AbstractServer:
        """Start the SSH honeypot server."""
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port
        )
        return server

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming SSH connection."""
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        session_id = self.new_session()

        if not self.check_rate_limit(src_ip):
            writer.close()
            await writer.wait_closed()
            return

        self.log_event("connection", src_ip=src_ip, src_port=src_port,
                       dst_port=self.port, session_id=session_id)

        try:
            # Send SSH banner
            writer.write(f"{self.banner}\r\n".encode())
            await writer.drain()

            # Read client banner
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            client_banner = client_banner.decode(errors="replace").strip()
            self.log_event("client_banner", src_ip=src_ip, src_port=src_port,
                           session_id=session_id, payload=client_banner)

            # Simulate auth loop
            attempts = 0
            while attempts < self.max_auth:
                try:
                    writer.write(b"\r\nlogin: ")
                    await writer.drain()
                    username = await asyncio.wait_for(reader.readline(), timeout=60)
                    username = username.decode(errors="replace").strip()

                    writer.write(b"password: ")
                    await writer.drain()
                    password = await asyncio.wait_for(reader.readline(), timeout=60)
                    password = password.decode(errors="replace").strip()

                    if not username and not password:
                        break

                    attempts += 1
                    self.log_event(
                        "login_attempt",
                        src_ip=src_ip, src_port=src_port,
                        dst_port=self.port, session_id=session_id,
                        username=username, password=password,
                    )

                    # Always deny but emulate shell on specific creds for engagement
                    if self.emulate_shell and attempts >= 2:
                        writer.write(b"\r\nLast login: Mon May 18 03:22:14 2026 from 10.0.0.1\r\n")
                        await writer.drain()
                        await self._fake_shell(reader, writer, src_ip, src_port, session_id, username)
                        break

                    writer.write(b"\r\nPermission denied, please try again.\r\n")
                    await writer.drain()

                except asyncio.TimeoutError:
                    break

            if attempts >= self.max_auth:
                self.log_event("brute_force_detected", src_ip=src_ip,
                               session_id=session_id, payload=f"{attempts} attempts")

        except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            self.log_event("disconnect", src_ip=src_ip, src_port=src_port,
                           session_id=session_id)

    async def _fake_shell(self, reader, writer, src_ip, src_port, session_id, username):
        """Simulate a basic shell to capture attacker commands."""
        prompt = f"{username}@darknet-srv:~$ ".encode()

        while True:
            try:
                writer.write(prompt)
                await writer.drain()

                data = await asyncio.wait_for(reader.readline(), timeout=120)
                cmd = data.decode(errors="replace").strip()

                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit", "logout"):
                    writer.write(b"logout\r\n")
                    await writer.drain()
                    break

                self.log_event(
                    "command_execution",
                    src_ip=src_ip, src_port=src_port,
                    session_id=session_id, username=username,
                    payload=cmd,
                )

                # Return fake output if we have it
                response = self.commands.get(cmd, f"-bash: {cmd.split()[0] if cmd.split() else cmd}: command not found")
                writer.write(f"{response}\r\n".encode())
                await writer.drain()

            except (asyncio.TimeoutError, ConnectionResetError):
                break
