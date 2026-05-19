"""Telnet Honeypot — emulates BusyBox login to capture IoT botnet credentials."""

import asyncio
from shadowtrap.services.base import BaseHoneypot


class TelnetHoneypot(BaseHoneypot):
    """Telnet honeypot targeting IoT botnet credential harvesting."""

    SERVICE_NAME = "telnet"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.banner = self.config.get("banner", "BusyBox v1.36.1 built-in shell (ash)")
        self.login_prompt = self.config.get("login_prompt", "darknet login: ")
        self.password_prompt = self.config.get("password_prompt", "Password: ")

    async def start(self) -> asyncio.AbstractServer:
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port
        )
        return server

    async def _handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        src_ip, src_port = peer[0], peer[1]
        session_id = self.new_session()

        if not self.check_rate_limit(src_ip):
            writer.close()
            return

        self.log_event("connection", src_ip=src_ip, src_port=src_port,
                       dst_port=self.port, session_id=session_id)

        try:
            writer.write(f"\r\n{self.banner}\r\n\r\n".encode())
            await writer.drain()

            attempts = 0
            max_attempts = 5

            while attempts < max_attempts:
                writer.write(self.login_prompt.encode())
                await writer.drain()
                username = await asyncio.wait_for(reader.readline(), timeout=60)
                username = username.decode(errors="replace").strip()

                writer.write(self.password_prompt.encode())
                await writer.drain()
                password = await asyncio.wait_for(reader.readline(), timeout=60)
                password = password.decode(errors="replace").strip()

                attempts += 1
                self.log_event(
                    "login_attempt",
                    src_ip=src_ip, src_port=src_port,
                    dst_port=self.port, session_id=session_id,
                    username=username, password=password,
                )

                if not username and not password:
                    break

                # Accept after a few tries to observe behavior
                if attempts >= 2:
                    writer.write(f"\r\n\r\n{self.banner}\r\n".encode())
                    await writer.drain()
                    await self._shell(reader, writer, src_ip, src_port, session_id, username)
                    break
                else:
                    writer.write(b"\r\nLogin incorrect\r\n\r\n")
                    await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            self.log_event("disconnect", src_ip=src_ip, session_id=session_id)

    async def _shell(self, reader, writer, src_ip, src_port, session_id, username):
        """Fake BusyBox shell."""
        prompt = f"# ".encode()
        while True:
            try:
                writer.write(prompt)
                await writer.drain()
                data = await asyncio.wait_for(reader.readline(), timeout=120)
                cmd = data.decode(errors="replace").strip()

                if not cmd:
                    continue
                if cmd.lower() in ("exit", "quit"):
                    break

                self.log_event(
                    "command_execution",
                    src_ip=src_ip, src_port=src_port,
                    session_id=session_id, username=username,
                    payload=cmd,
                )

                # Mimic common IoT botnet commands
                if "wget" in cmd or "curl" in cmd or "tftp" in cmd:
                    self.log_event("malware_download_attempt",
                                   src_ip=src_ip, session_id=session_id, payload=cmd)
                    writer.write(b"Connecting... failed: Connection timed out.\r\n")
                elif cmd == "cat /proc/cpuinfo":
                    writer.write(b"processor\t: 0\nmodel name\t: ARMv7 Processor rev 4\n")
                elif cmd == "uname -a":
                    writer.write(b"Linux darknet 4.14.0 #1 SMP armv7l GNU/Linux\r\n")
                else:
                    writer.write(f"-sh: {cmd.split()[0]}: not found\r\n".encode())

                await writer.drain()

            except (asyncio.TimeoutError, ConnectionResetError):
                break
