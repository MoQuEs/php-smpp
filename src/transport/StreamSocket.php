<?php

namespace smpp\transport;

use smpp\exceptions\SocketTransportException;

/**
 * Stream-based TCP / SSL / TLS transport for SMPP.
 *
 * Uses PHP stream wrappers (stream_socket_client) so it can handle plain-text
 * and encrypted connections in one class simply by choosing a scheme:
 *
 *   'tcp'  – plain TCP  (default, identical behaviour to the Socket class)
 *   'ssl'  – SSLv3 / TLS negotiated (legacy; prefer 'tls' for new deployments)
 *   'tls'  – TLS only
 *
 * SSL/TLS options (cafile, local_cert, local_pk, passphrase, …) can be passed
 * as the $sslOptions array and are forwarded verbatim to the stream context.
 * Certificate verification is controlled separately via setSslVerification().
 *
 * Requires ext-openssl for ssl:// and tls:// schemes.
 */
class StreamSocket extends Transport
{
    /** @var resource|null Active stream connection */
    protected $stream = null;

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Attempt a single stream_socket_client() connection.
     * Returns the stream resource on success, or false on failure.
     */
    private function tryConnect(string $address, string $hostname): mixed
    {
        $connectTimeout = max(1, (int) ceil($this->sendTimeoutMs / 1000));
        $context        = $this->buildStreamContext($hostname);
        $errno          = 0;
        $errstr         = '';

        $this->logDebug("Connecting to $address...");

        $stream = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            $connectTimeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($stream === false) {
            $this->logDebug("Connection to $address failed: $errstr ($errno)");
            return false;
        }

        stream_set_blocking($stream, true);
        $this->applyStreamTimeout($stream, $this->recvTimeoutMs);
        $this->logDebug("Connected to $address!");

        return $stream;
    }

    // -------------------------------------------------------------------------
    // TransportInterface implementation
    // -------------------------------------------------------------------------

    /**
     * {@inheritdoc}
     *
     * IPv6 addresses are tried before IPv4 unless $forceIpv4 is set.
     * For ssl/tls schemes the original hostname is passed as the SNI peer name.
     */
    public function open(): void
    {
        foreach ($this->hosts as [$hostname, $port, $ip6s, $ip4s]) {
            if (!self::$forceIpv4 && !empty($ip6s)) {
                foreach ($ip6s as $ip) {
                    $stream = $this->tryConnect("{$this->scheme}://[{$ip}]:{$port}", $hostname);
                    if ($stream !== false) {
                        $this->stream = $stream;
                        return;
                    }
                }
            }

            if (!self::$forceIpv6 && !empty($ip4s)) {
                foreach ($ip4s as $ip) {
                    $stream = $this->tryConnect("{$this->scheme}://{$ip}:{$port}", $hostname);
                    if ($stream !== false) {
                        $this->stream = $stream;
                        return;
                    }
                }
            }
        }

        throw new SocketTransportException('Could not connect to any of the specified hosts');
    }

    /** {@inheritdoc} */
    public function close(): void
    {
        if (is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }

    /** {@inheritdoc} */
    public function isOpen(): bool
    {
        if ($this->stream === null || !is_resource($this->stream)) {
            return false;
        }
        return !feof($this->stream);
    }

    /** {@inheritdoc} */
    public function hasData(): bool
    {
        $r      = [$this->stream];
        $w      = null;
        $e      = null;
        $result = stream_select($r, $w, $e, 0, 0);

        if ($result === false) {
            throw new SocketTransportException('Could not examine stream; stream_select() failed');
        }

        return !empty($r);
    }

    /** {@inheritdoc} */
    public function read(int $length): string|false
    {
        $data = @fread($this->stream, $length);

        if ($data === false) {
            throw new SocketTransportException(
                'Could not read ' . $length . ' bytes from stream'
            );
        }

        if ($data === '') {
            // EOF or timeout – signal the caller to stop
            return false;
        }

        return $data;
    }

    /** {@inheritdoc} */
    public function readAll(int $length): string
    {
        $data         = '';
        $bytesRead    = 0;
        [$sec, $usec] = $this->msToSelectArgs($this->recvTimeoutMs);

        while ($bytesRead < $length) {
            $chunk = @fread($this->stream, $length - $bytesRead);

            if ($chunk === false) {
                throw new SocketTransportException(
                    'Could not read ' . $length . ' bytes from stream'
                );
            }

            if ($chunk === '') {
                $meta = stream_get_meta_data($this->stream);
                if ($meta['timed_out'] ?? false) {
                    throw new SocketTransportException('Timed out waiting for data on stream');
                }
                throw new SocketTransportException(
                    'Stream closed unexpectedly while reading ' . $length . ' bytes'
                );
            }

            $bytesRead += strlen($chunk);
            $data      .= $chunk;

            if ($bytesRead < $length) {
                $r      = [$this->stream];
                $w      = null;
                $e      = null;
                $result = stream_select($r, $w, $e, $sec, $usec);

                if ($result === false) {
                    throw new SocketTransportException('Could not examine stream; stream_select() failed');
                }
                if (empty($r)) {
                    throw new SocketTransportException('Timed out waiting for data on stream');
                }
            }
        }

        return $data;
    }

    /** {@inheritdoc} */
    public function write(string $buffer, int $length): void
    {
        $remaining    = $length;
        [$sec, $usec] = $this->msToSelectArgs($this->sendTimeoutMs);

        while ($remaining > 0) {
            $wrote = @fwrite($this->stream, $buffer, $remaining);

            if ($wrote === false) {
                throw new SocketTransportException(
                    'Could not write ' . $length . ' bytes to stream'
                );
            }

            $remaining -= $wrote;

            if ($remaining > 0) {
                $buffer = substr($buffer, $wrote);
                $r      = null;
                $w      = [$this->stream];
                $e      = null;
                $result = stream_select($r, $w, $e, $sec, $usec);

                if ($result === false) {
                    throw new SocketTransportException('Could not examine stream; stream_select() failed');
                }
                if (empty($w)) {
                    throw new SocketTransportException('Timed out waiting to write data on stream');
                }
            }
        }
    }

    /** Apply live recv timeout to an already-open stream connection. */
    protected function onRecvTimeoutChanged(int $timeout): void
    {
        if ($this->stream !== null && is_resource($this->stream)) {
            $this->applyStreamTimeout($this->stream, $timeout);
        }
    }
}

