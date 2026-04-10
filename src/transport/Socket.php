<?php


namespace smpp\transport;

use smpp\exceptions\SocketTransportException;

!defined('MSG_DONTWAIT') && define('MSG_DONTWAIT', 64);

/**
 * TCP Socket Transport for use with multiple protocols.
 * Supports connection pools and IPv6 in addition to providing a few public methods to make life easier.
 * It's primary purpose is long-running connections, since it don't support socket re-use, ip-blacklisting, etc.
 * It assumes a blocking/synchronous architecture, and will block when reading or writing, but will enforce timeouts.
 *
 * Copyright (C) 2011 OnlineCity
 * Licensed under the MIT license, which can be read at: http://www.opensource.org/licenses/mit-license.php
 * @author hd@onlinecity.dk
 */
class Socket extends Transport
{
    protected $socket;
    protected array $hosts = [];
    protected $persist;
    protected $debugHandler;
    public bool $debug;

    public static int  $defaultSendTimeout = 100;
    public static int  $defaultRecvTimeout = 750;
    public static bool $defaultDebug = false;


    public static bool $forceIpv6  = false;
    public static bool $forceIpv4  = false;
    public static bool $randomHost = false;

    /**
     * Construct a new socket for this transport to use.
     *
     * @param array $hosts list of hosts to try.
     * @param mixed $ports list of ports to try, or a single common port
     * @param boolean $persist use persistent sockets
     * @param mixed $debugHandler callback for debug info
     */
    public function __construct(array $hosts, $ports, $persist = false, $debugHandler = null)
    {
        $this->debug = self::$defaultDebug;
        $this->debugHandler = $debugHandler ? $debugHandler : 'error_log';

        // Deal with optional port
        $h = [];
        foreach ($hosts as $key => $host) {
            $h[] = [$host, is_array($ports) ? $ports[$key] : $ports];
        }
        if (self::$randomHost) {
            shuffle($h);
        }
        $this->resolveHosts($h);

        $this->persist = $persist;
    }

    /**
     * Get a reference to the socket.
     * You should use the public functions rather than the socket directly
     */
    public function getSocket()
    {
        return $this->socket;
    }

    /**
     * Get an arbitrary option
     *
     * @param integer $option
     * @param integer $lvl
     *
     * @return array|false|int
     */
    public function getSocketOption($option, $lvl = SOL_SOCKET)
    {
        return socket_get_option($this->socket, $lvl, $option);
    }

    /**
     * Set an arbitrary option
     *
     * @param integer $option
     * @param mixed $value
     * @param integer $lvl
     *
     * @return bool
     */
    public function setSocketOption($option, $value, $lvl = SOL_SOCKET)
    {
        return socket_set_option($this->socket, $lvl, $option, $value);
    }

    /**
     * Sets the send timeout.
     * Returns true on success, or false.
     * @param int $timeout Timeout in milliseconds.
     * @return boolean
     */
    public function setSendTimeout(int $timeout): bool
    {
        if (!$this->isOpen()) {
            self::$defaultSendTimeout = $timeout;
            return true;
        } else {
            return socket_set_option(
                $this->socket,
                SOL_SOCKET,
                SO_SNDTIMEO,
                $this->millisecToSolArray($timeout)
            );
        }
    }

    /**
     * Sets the receive timeout.
     * Returns true on success, or false.
     * @param int $timeout Timeout in milliseconds.
     * @return boolean
     */
    public function setRecvTimeout(int $timeout): bool
    {
        if (!$this->isOpen()) {
            self::$defaultRecvTimeout = $timeout;
            return true;
        } else {
            return socket_set_option(
                $this->socket,
                SOL_SOCKET,
                SO_RCVTIMEO,
                $this->millisecToSolArray($timeout)
            );
        }
    }

    /**
     * Check if the socket is constructed, and there are no exceptions on it
     * Returns false if it's closed.
     * Throws SocketTransportException is state could not be ascertained
     * @throws SocketTransportException
     */
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

        // if there is an exception on our socket it's probably dead
        if (!empty($e)) {
            return false;
        }

        return true;
    }

    /**
     * Convert a milliseconds into a socket sec+usec array
     * @param integer $milliseconds
     * @return array
     */
    private function millisecToSolArray($milliseconds)
    {
        $usec = $milliseconds * 1000;
        return ['sec' => (int)floor($usec / 1000000), 'usec' => $usec % 1000000];
    }

    /**
     * Open the socket, trying to connect to each host in succession.
     * This will prefer IPv6 connections if forceIpv4 is not enabled.
     * If all hosts fail, a SocketTransportException is thrown.
     *
     * @throws SocketTransportException
     */
    public function open(): void
    {
        // Initialize to null so we can safely check before closing
        $socket6 = null;
        $socket4 = null;

        if (!self::$forceIpv4) {
            $socket6 = @socket_create(AF_INET6, SOCK_STREAM, SOL_TCP);
            if ($socket6 === false) {
                throw new SocketTransportException(
                    'Could not create socket; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }
            socket_set_option(
                $socket6,
                SOL_SOCKET,
                SO_SNDTIMEO,
                $this->millisecToSolArray(self::$defaultSendTimeout)
            );
            socket_set_option(
                $socket6,
                SOL_SOCKET,
                SO_RCVTIMEO,
                $this->millisecToSolArray(self::$defaultRecvTimeout)
            );
        }
        if (!self::$forceIpv6) {
            $socket4 = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if ($socket4 === false) {
                throw new SocketTransportException('Could not create socket; ' . socket_strerror(socket_last_error()), socket_last_error());
            }
            socket_set_option($socket4, SOL_SOCKET, SO_SNDTIMEO, $this->millisecToSolArray(self::$defaultSendTimeout));
            socket_set_option($socket4, SOL_SOCKET, SO_RCVTIMEO, $this->millisecToSolArray(self::$defaultRecvTimeout));
        }
        $it = new \ArrayIterator($this->hosts);
        while ($it->valid()) {
            list($hostname, $port, $ip6s, $ip4s) = $it->current();
            if (!self::$forceIpv4 && !empty($ip6s)) { // Attempt IPv6s first
                foreach ($ip6s as $ip) {
                    if ($this->debug) {
                        call_user_func($this->debugHandler, "Connecting to $ip:$port...");
                    }
                    $r = @socket_connect($socket6, $ip, $port);
                    if ($r) {
                        if ($this->debug) {
                            call_user_func($this->debugHandler, "Connected to $ip:$port!");
                        }
                        if ($socket4 !== null) {
                            @socket_close($socket4);
                        }
                        $this->socket = $socket6;
                        return;
                    } elseif ($this->debug) {
                        call_user_func($this->debugHandler, "Socket connect to $ip:$port failed; " . socket_strerror(socket_last_error()));
                    }
                }
            }
            if (!self::$forceIpv6 && !empty($ip4s)) {
                foreach ($ip4s as $ip) {
                    if ($this->debug) call_user_func($this->debugHandler, "Connecting to $ip:$port...");
                    $r = @socket_connect($socket4, $ip, $port);
                    if ($r) {
                        if ($this->debug) call_user_func($this->debugHandler, "Connected to $ip:$port!");
                        if ($socket6 !== null) {
                            @socket_close($socket6);
                        }
                        $this->socket = $socket4;
                        return;
                    } elseif ($this->debug) {
                        call_user_func($this->debugHandler, "Socket connect to $ip:$port failed; " . socket_strerror(socket_last_error()));
                    }
                }
            }
            $it->next();
        }
        throw new SocketTransportException('Could not connect to any of the specified hosts');
    }

    /**
     * Do a clean shutdown of the socket.
     * Since we don't reuse sockets, we can just close and forget about it,
     * but we choose to wait (linger) for the last data to come through.
     */
    public function close(): void
    {
        $arrOpt = ['l_onoff' => 1, 'l_linger' => 1];
        socket_set_block($this->socket);
        socket_set_option($this->socket, SOL_SOCKET, SO_LINGER, $arrOpt);
        socket_close($this->socket);
    }

    /**
     * Check if there is data waiting for us on the wire
     * @return boolean
     * @throws SocketTransportException
     */
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

        if (!empty($r)) {
            return true;
        }

        return false;
    }

    /**
     * Read up to $length bytes from the socket.
     * Does not guarantee that all the bytes are read.
     * Returns false on EOF
     * Returns false on timeout (technically EAGAIN error).
     * Throws SocketTransportException if data could not be read.
     *
     * @param integer $length
     * @return mixed
     * @throws SocketTransportException
     */
    public function read(int $length): string|false
    {
        $d = socket_read($this->socket, $length, PHP_BINARY_READ);
        // sockets give EAGAIN on timeout
        if ($d === false && socket_last_error() === SOCKET_EAGAIN) {
            return false;
        }
        if ($d === false) {
            throw new SocketTransportException(
                'Could not read ' . $length . ' bytes from socket; ' . socket_strerror(socket_last_error()),
                socket_last_error()
            );
        }
        if ($d === '') {
            return false;
        }

        return $d;
    }

    /**
     * Read all the bytes, and block until they are read.
     * Timeout throws SocketTransportException
     *
     * @param integer $length
     * @return string
     */
    public function readAll(int $length): string
    {
        $d = "";
        $bytesRead = 0;
        $readTimeout = socket_get_option($this->socket, SOL_SOCKET, SO_RCVTIMEO);
        while ($bytesRead < $length) {
            $buf = '';
            $received = socket_recv($this->socket, $buf, $length - $bytesRead, MSG_DONTWAIT);
            if ($received === false) {
                throw new SocketTransportException(
                    'Could not read ' . $length . ' bytes from socket; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }
            $bytesRead += $received;
            $d .= $buf;
            if ($bytesRead == $length) {
                return $d;
            }

            // wait for data to be available, up to timeout
            $readSockets = [$this->socket];
            $w = null;
            $e = [$this->socket];
            $res = socket_select($readSockets, $w, $e, $readTimeout['sec'], $readTimeout['usec']);

            // check
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
        return $d;
    }

    /**
     * Write (all) data to the socket.
     * Timeout throws SocketTransportException
     *
     * @param $buffer
     * @param integer $length
     */
    public function write(string $buffer, int $length): void
    {
        $remaining = $length;
        $writeTimeout = socket_get_option($this->socket, SOL_SOCKET, SO_SNDTIMEO);

        while ($remaining > 0) {
            $wrote = socket_write($this->socket, $buffer, $remaining);
            if ($wrote === false) {
                throw new SocketTransportException(
                    'Could not write ' . $length . ' bytes to socket; ' . socket_strerror(socket_last_error()),
                    socket_last_error()
                );
            }
            $remaining -= $wrote;
            if ($remaining == 0) {
                return;
            }

            $buffer = substr($buffer, $wrote);

            // wait for the socket to accept more data, up to timeout
            $r = null;
            $w = [$this->socket];
            $e = [$this->socket];
            $res = socket_select($r, $w, $e, $writeTimeout['sec'], $writeTimeout['usec']);

            // check
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

    /**
     * {@inheritdoc}
     *
     * Plain TCP sockets do not support SSL/TLS – this method is a no-op.
     * Use StreamSocket with scheme 'ssl' or 'tls' for encrypted connections.
     */
    public function setSslVerification(bool $verify): void
    {
        // no-op: Socket is plain TCP only
    }
}
