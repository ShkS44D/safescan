"""Local-socket tests for TCP discovery and service identification."""

import socket
import threading
import unittest

from scanner import port_scanner


class LocalServer:
    def __init__(self, response: bytes, read_request: bool = False):
        self.response = response
        self.read_request = read_request
        self.request = b""
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        with self.listener:
            connection, _ = self.listener.accept()
            with connection:
                if self.read_request:
                    connection.settimeout(2)
                    self.request = connection.recv(4096)
                connection.sendall(self.response)

    def start(self):
        self.thread.start()
        return self

    def join(self):
        self.thread.join(timeout=3)


class ScannerTests(unittest.TestCase):
    def test_ssh_banner_and_closed_port(self):
        server = LocalServer(b"SSH-2.0-OpenSSH_9.6\r\n").start()
        result = port_scanner.scan_ports("127.0.0.1", "localhost", server.port, server.port)
        server.join()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["service"], "ssh")
        self.assertEqual(result[0]["product"], "OpenSSH")
        self.assertEqual(result[0]["version"], "9.6")
        self.assertEqual(result[0]["confidence"], "banner")

        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        self.assertEqual(
            port_scanner.scan_ports("127.0.0.1", "localhost", closed_port, closed_port), []
        )

    def test_http_head_and_server_header(self):
        response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"
        server = LocalServer(response, read_request=True).start()
        port_scanner.HTTP_PORTS.add(server.port)
        try:
            result = port_scanner.scan_ports("127.0.0.1", "scanner.test", server.port, server.port)
        finally:
            port_scanner.HTTP_PORTS.discard(server.port)
        server.join()
        self.assertIn(b"HEAD / HTTP/1.1", server.request)
        self.assertIn(b"Host: scanner.test", server.request)
        self.assertEqual(result[0]["service"], "http")
        self.assertEqual(result[0]["product"], "nginx")
        self.assertEqual(result[0]["version"], "1.24.0")

    def test_banner_is_sanitized_and_capped(self):
        banner = port_scanner.sanitize_banner(b"hello\x00world " + b"x" * 400)
        self.assertNotIn("\x00", banner)
        self.assertLessEqual(len(banner), 200)

    def test_port_fallback_is_labeled_as_guess(self):
        identity = port_scanner.identify_service(5432, "")
        self.assertEqual(identity["service"], "postgresql")
        self.assertEqual(identity["confidence"], "port-guess")


if __name__ == "__main__":
    unittest.main()
