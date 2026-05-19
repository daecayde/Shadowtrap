"""FTP Honeypot — emulates vsftpd to capture credentials and file operations."""

import asyncio
from shadowtrap.services.base import BaseHoneypot


class FTPHoneypot(BaseHoneypot):
    """FTP honeypot that captures login attempts and file operation commands."""

    SERVICE_NAME = "ftp"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.banner = self.config.get("banner", "220 (vsFTPd 3.0.5)")
        self.max_attempts = self.config.get("max_login_attempts", 5)
        self.fake_files = self.config.get("fake_files", [
            "backup.sql.gz", "credentials.txt", ".env", "id_rsa"
        ])

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
            writer.write(f"{self.banner}\r\n".encode())
            await writer.drain()

            username = ""
            attempts = 0
            authenticated = False

            while attempts < self.max_attempts:
                data = await asyncio.wait_for(reader.readline(), timeout=60)
                cmd = data.decode(errors="replace").strip()

                if not cmd:
                    break

                parts = cmd.split(" ", 1)
                command = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if command == "USER":
                    username = arg
                    writer.write(b"331 Please specify the password.\r\n")
                    await writer.drain()

                elif command == "PASS":
                    attempts += 1
                    self.log_event(
                        "login_attempt",
                        src_ip=src_ip, src_port=src_port,
                        dst_port=self.port, session_id=session_id,
                        username=username, password=arg,
                    )
                    # Let them in after a couple tries to see what they do
                    if attempts >= 2:
                        authenticated = True
                        writer.write(b"230 Login successful.\r\n")
                        await writer.drain()
                        await self._ftp_session(reader, writer, src_ip, src_port, session_id, username)
                        break
                    else:
                        writer.write(b"530 Login incorrect.\r\n")
                        await writer.drain()

                elif command == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break

                else:
                    writer.write(b"530 Please login with USER and PASS.\r\n")
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

    async def _ftp_session(self, reader, writer, src_ip, src_port, session_id, username):
        """Handle authenticated FTP session — capture commands."""
        while True:
            try:
                data = await asyncio.wait_for(reader.readline(), timeout=120)
                cmd = data.decode(errors="replace").strip()

                if not cmd:
                    continue

                parts = cmd.split(" ", 1)
                command = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                self.log_event(
                    "ftp_command",
                    src_ip=src_ip, src_port=src_port,
                    session_id=session_id, username=username,
                    payload=cmd,
                )

                if command == "PWD":
                    writer.write(b'257 "/home/admin" is the current directory\r\n')
                elif command == "LIST" or command == "LS":
                    listing = "150 Here comes the directory listing.\r\n"
                    for f in self.fake_files:
                        listing += f"-rw-r--r--    1 admin    admin        4096 May 15 09:23 {f}\r\n"
                    listing += "226 Directory send OK.\r\n"
                    writer.write(listing.encode())
                elif command == "RETR" or command == "GET":
                    self.log_event("file_download_attempt", src_ip=src_ip,
                                   session_id=session_id, payload=arg)
                    writer.write(b"550 Failed to open file.\r\n")
                elif command == "STOR" or command == "PUT":
                    self.log_event("file_upload_attempt", src_ip=src_ip,
                                   session_id=session_id, payload=arg)
                    writer.write(b"553 Could not create file.\r\n")
                elif command == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break
                elif command == "SYST":
                    writer.write(b"215 UNIX Type: L8\r\n")
                elif command == "TYPE":
                    writer.write(b"200 Switching to Binary mode.\r\n")
                else:
                    writer.write(f"502 Command not implemented: {command}\r\n".encode())

                await writer.drain()

            except (asyncio.TimeoutError, ConnectionResetError):
                break
