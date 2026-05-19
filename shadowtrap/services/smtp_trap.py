"""SMTP Honeypot — captures email relay attempts and sender information."""

import asyncio
from shadowtrap.services.base import BaseHoneypot


class SMTPHoneypot(BaseHoneypot):
    """SMTP honeypot that captures email sending attempts."""

    SERVICE_NAME = "smtp"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.banner = self.config.get("banner", "220 mail.example.com ESMTP Postfix (Ubuntu)")

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

            mail_from = ""
            rcpt_to = []
            data_mode = False
            email_data = []

            while True:
                data = await asyncio.wait_for(reader.readline(), timeout=60)
                line = data.decode(errors="replace").strip()

                if not line and not data_mode:
                    break

                if data_mode:
                    if line == ".":
                        data_mode = False
                        email_content = "\n".join(email_data)
                        self.log_event(
                            "email_captured",
                            src_ip=src_ip, session_id=session_id,
                            payload=email_content[:2000],
                            username=mail_from,
                        )
                        writer.write(b"250 2.0.0 Ok: queued as FAKE001\r\n")
                        await writer.drain()
                        email_data = []
                    else:
                        email_data.append(line)
                    continue

                cmd = line.upper()

                if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                    hostname = line.split(" ", 1)[1] if " " in line else "unknown"
                    self.log_event("smtp_helo", src_ip=src_ip,
                                   session_id=session_id, payload=hostname)
                    writer.write(f"250-mail.example.com\r\n250-SIZE 10240000\r\n250 OK\r\n".encode())

                elif cmd.startswith("MAIL FROM"):
                    mail_from = line.split(":", 1)[1].strip() if ":" in line else ""
                    self.log_event("smtp_mail_from", src_ip=src_ip,
                                   session_id=session_id, payload=mail_from)
                    writer.write(b"250 2.1.0 Ok\r\n")

                elif cmd.startswith("RCPT TO"):
                    recipient = line.split(":", 1)[1].strip() if ":" in line else ""
                    rcpt_to.append(recipient)
                    self.log_event("smtp_rcpt_to", src_ip=src_ip,
                                   session_id=session_id, payload=recipient)
                    writer.write(b"250 2.1.5 Ok\r\n")

                elif cmd == "DATA":
                    data_mode = True
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")

                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break

                elif cmd == "RSET":
                    mail_from = ""
                    rcpt_to = []
                    writer.write(b"250 2.0.0 Ok\r\n")

                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")

                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
