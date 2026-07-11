import socket
import time

import pytest
import os

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 2525))

def port_is_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False

if not port_is_open(SMTP_HOST, SMTP_PORT):
    pytestmark = pytest.mark.skip(reason=f"SMTP honeypot not running on {SMTP_HOST}:{SMTP_PORT}")


def send_cmd(sock, cmd):
    sock.sendall((cmd + "\r\n").encode())
    time.sleep(0.2)
    return sock.recv(4096).decode()


def test_smtp_basic_flow():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SMTP_HOST, SMTP_PORT))

    banner = sock.recv(1024).decode()
    assert "SMTP" in banner

    assert "250" in send_cmd(sock, "HELO test.com")
    assert "250" in send_cmd(sock, "MAIL FROM:<attacker@test.com>")
    assert "250" in send_cmd(sock, "RCPT TO:<victim@test.com>")
    assert "354" in send_cmd(sock, "DATA")

    sock.sendall(b"Subject: Test Mail\r\n\r\nHello\r\n.\r\n")
    time.sleep(0.2)
    response = sock.recv(1024).decode()
    assert "250" in response

    assert "221" in send_cmd(sock, "QUIT")

    sock.close()
