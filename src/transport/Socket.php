<?php


namespace smpp\transport;

use smpp\exceptions\SocketTransportException;

!defined('MSG_DONTWAIT') && define('MSG_DONTWAIT', 64);

/**
 * Socket transport with two backends under one API:
 * - tcp: native ext-sockets
 * - ssl/tls: stream adapter
 */
class Socket extends Transport
{
    /** @var resource|\Socket|null Active ext-socket for tcp backend */
    protected $socket = null;

    private function createTcpSocket(int $family): mixed
    {
        $socket = @socket_create($family, SOCK_STREAM, SOL_TCP);
        if ($socket === false) {
            throw new SocketTransportException(
                'Could not create socket; ' . socket_strerror(socket_last_error()),
                socket_last_error()
            );
        }

        socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, $this->msToSocketTimeout($this->sendTimeoutMs));
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, $this->msToSocketTimeout($this->recvTimeoutMs));

        return $socket;
    }

    public function open(): void
    {
        $socket6 = null;
        $socket4 = null;

        if (!self::$forceIpv4) {
            $socket6 = $this->createTcpSocket(AF_INET6);
        }
        if (!self::$forceIpv6) {
            $socket4 = $this->createTcpSocket(AF_INET);
        }

        foreach ($this->hosts as [$hostname, $port, $ip6s, $ip4s]) {
            if (!self::$forceIpv4 && !empty($ip6s)) {
                foreach ($ip6s as $ip) {
                    $this->logDebug("Connecting to $ip:$port...");
                    $connected = @socket_connect($socket6, $ip, $port);
                    if ($connected) {
                        $this->logDebug("Connected to $ip:$port!");
                        if ($socket4 !== null) {
                            @socket_close($socket4);
                        }
                        $this->socket = $socket6;
                        return;
                    }
                    $this->logDebug('Socket connect to ' . $ip . ':' . $port . ' failed; ' . socket_strerror(socket_last_error()));
                }
            }

            if (!self::$forceIpv6 && !empty($ip4s)) {
                foreach ($ip4s as $ip) {
                    $this->logDebug("Connecting to $ip:$port...");
                    $connected = @socket_connect($socket4, $ip, $port);
                    if ($connected) {
                        $this->logDebug("Connected to $ip:$port!");
                        if ($socket6 !== null) {
                            @socket_close($socket6);
                        }
                        $this->socket = $socket4;
                        return;
                    }
                    $this->logDebug('Socket connect to ' . $ip . ':' . $port . ' failed; ' . socket_strerror(socket_last_error()));
                }
            }
        }

        if ($socket6 !== null && $socket6 !== $this->socket) {
            @socket_close($socket6);
        }
        if ($socket4 !== null && $socket4 !== $this->socket) {
            @socket_close($socket4);
        }

        throw new SocketTransportException('Could not connect to any of the specified hosts');
    }

    public function close(): void
    {
        if ($this->socket !== null && (is_resource($this->socket) || $this->socket instanceof \Socket)) {
            $arrOpt = ['l_onoff' => 1, 'l_linger' => 1];
            @socket_set_block($this->socket);
            @socket_set_option($this->socket, SOL_SOCKET, SO_LINGER, $arrOpt);
            @socket_close($this->socket);
        }
        $this->socket = null;
    }

    public function isOpen(): bool
    {
        if ($this->socket === null || (!is_resource($this->socket) && !($this->socket instanceof \Socket))) {
            return false;
        }

        $r = null;
        $w = null;
        $e = [$this->socket];
        $res = socket_select($r, $w, $e, 0);

        if ($res === false) {
            throw new SocketTransportException(
                'Could not examine socket; ' . socket_strerror(socket_last_error()),
                socket_last_error()
            );
        }

        return empty($e);
    }

    public function hasData(): bool
    {
        $r = [$this->socket];
        $w = null;
        $e = null;
        $res = socket_select($r, $w, $e, 0);

        if ($res === false) {
            throw new SocketTransportException(
                'Could not examine socket; ' . socket_strerror(socket_last_error()),
                socket_last_error()
            );
        }

        return !empty($r);
    }

    public function read(int $length): string|false
    {
        $data = socket_read($this->socket, $length, PHP_BINARY_READ);
        if ($data === false && socket_last_error() === SOCKET_EAGAIN) {
            return false;
        }
        if ($data === false) {
            throw new SocketTransportException(
                'Could not read ' . $length . ' bytes from socket; ' . socket_strerror(socket_last_error()),
                socket_last_error()
            );
        }
        if ($data === '') {
            return false;
        }

        return $data;
    }

    public function readAll(int $length): string
    {
        $data = '';
        $bytesRead = 0;
        [$sec, $usec] = $this->msToSelectArgs($this->recvTimeoutMs);

        while ($bytesRead < $length) {
            $buf = '';
            $received = socket_recv($this->socket, $buf, $length - $bytesRead, MSG_DONTWAIT);
            if ($received === false) {
                throw new SocketTransportException(
                    'Could not read ' . $length . ' bytes from socket; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }
            if ($received === 0) {
                throw new SocketTransportException('Socket closed unexpectedly while reading ' . $length . ' bytes');
            }

            $bytesRead += $received;
            $data .= $buf;

            if ($bytesRead < $length) {
                $readSockets = [$this->socket];
                $w = null;
                $e = [$this->socket];
                $res = socket_select($readSockets, $w, $e, $sec, $usec);

                if ($res === false) {
                    throw new SocketTransportException(
                        'Could not examine socket; ' . socket_strerror(socket_last_error()),
                        socket_last_error()
                    );
                }
                if (!empty($e)) {
                    throw new SocketTransportException(
                        'Socket exception while waiting for data; ' . socket_strerror(socket_last_error()),
                        socket_last_error()
                    );
                }
                if (empty($readSockets)) {
                    throw new SocketTransportException('Timed out waiting for data on socket');
                }
            }
        }

        return $data;
    }

    public function write(string $buffer, int $length): void
    {
        $remaining = $length;
        [$sec, $usec] = $this->msToSelectArgs($this->sendTimeoutMs);

        while ($remaining > 0) {
            $wrote = socket_write($this->socket, $buffer, $remaining);
            if ($wrote === false) {
                throw new SocketTransportException(
                    'Could not write ' . $length . ' bytes to socket; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }

            $remaining -= $wrote;
            if ($remaining === 0) {
                return;
            }

            $buffer = substr($buffer, $wrote);
            $r = null;
            $w = [$this->socket];
            $e = [$this->socket];
            $res = socket_select($r, $w, $e, $sec, $usec);

            if ($res === false) {
                throw new SocketTransportException(
                    'Could not examine socket; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }
            if (!empty($e)) {
                throw new SocketTransportException(
                    'Socket exception while waiting to write data; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }
            if (empty($w)) {
                throw new SocketTransportException('Timed out waiting to write data on socket');
            }
        }
    }

    public function setSendTimeout(int $timeout): bool
    {
        parent::setSendTimeout($timeout);

        if ($this->socket === null || (!is_resource($this->socket) && !($this->socket instanceof \Socket))) {
            return true;
        }

        return socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, $this->msToSocketTimeout($timeout));
    }

    protected function onRecvTimeoutChanged(int $timeout): void
    {
        if ($this->socket !== null && (is_resource($this->socket) || $this->socket instanceof \Socket)) {
            socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, $this->msToSocketTimeout($timeout));
        }
    }
}
