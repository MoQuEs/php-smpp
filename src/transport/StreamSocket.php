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

    /** @var array Resolved host pool: [hostname, port, ip6s[], ip4s[]] */
    protected array $hosts = [];

    /** @var string Connection scheme: 'tcp', 'ssl' or 'tls' */
    protected string $scheme;

    /** @var array Extra SSL context options forwarded to stream_context_create() */
    protected array $sslOptions;

    /**
     * Whether to verify the peer certificate and hostname.
     * Controlled by setSslVerification(). Defaults to true (secure).
     */
    protected bool $verifySsl = true;

    public bool $debug;

    /** @var callable */
    protected $debugHandler;

    /** @var int Send timeout in milliseconds */
    protected int $sendTimeoutMs;

    /** @var int Receive timeout in milliseconds */
    protected int $recvTimeoutMs;

    public static int  $defaultSendTimeout = 100;
    public static int  $defaultRecvTimeout = 750;
    public static bool $defaultDebug       = false;

    public static bool $forceIpv6  = false;
    public static bool $forceIpv4  = false;
    public static bool $randomHost = false;

    /**
     * @param array         $hosts        List of hostnames / IPs to try
     * @param array|int     $ports        List of ports (one per host) or a single common port
     * @param string        $scheme       'tcp', 'ssl' or 'tls'
     * @param array         $sslOptions   Additional SSL context options (cafile, local_cert, …)
     * @param callable|null $debugHandler Callback for debug messages; defaults to error_log
     */
    public function __construct(
        array     $hosts,
        array|int $ports,
        string    $scheme       = 'tcp',
        array     $sslOptions   = [],
        mixed     $debugHandler = null
    ) {
        if (!in_array($scheme, ['tcp', 'ssl', 'tls'], true)) {
            throw new \InvalidArgumentException(
                "Scheme must be 'tcp', 'ssl' or 'tls', got: '$scheme'"
            );
        }

        $this->scheme        = $scheme;
        $this->sslOptions    = $sslOptions;
        $this->debug         = self::$defaultDebug;
        $this->debugHandler  = $debugHandler ?? 'error_log';
        $this->sendTimeoutMs = self::$defaultSendTimeout;
        $this->recvTimeoutMs = self::$defaultRecvTimeout;

        $h = [];
        foreach ($hosts as $key => $host) {
            $h[] = [$host, is_array($ports) ? $ports[$key] : $ports];
        }
        if (self::$randomHost) {
            shuffle($h);
        }
        $this->resolveHosts($h);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /**
     * Build a stream context for the given hostname.
     *
     * For ssl/tls schemes the context merges user-supplied $sslOptions with the
     * hostname (used as SNI peer_name) and the verifySsl flags.
     * verifySsl always takes final precedence so that setSslVerification() is
     * never silently overridden by something in $sslOptions.
     */
    private function buildContext(string $hostname): mixed
    {
        if ($this->scheme === 'tcp') {
            return stream_context_create([]);
        }

        $ssl = array_merge(
            // Low-priority defaults
            ['peer_name' => $hostname],
            // User-supplied extras (cafile, local_cert, passphrase, …)
            $this->sslOptions,
            // verifySsl always wins – must be last
            [
                'verify_peer'      => $this->verifySsl,
                'verify_peer_name' => $this->verifySsl,
            ]
        );

        return stream_context_create(['ssl' => $ssl]);
    }

    /**
     * Attempt a single stream_socket_client() connection.
     * Returns the stream resource on success, or false on failure.
     */
    private function tryConnect(string $address, string $hostname): mixed
    {
        $connectTimeout = max(1, (int) ceil($this->sendTimeoutMs / 1000));
        $context        = $this->buildContext($hostname);
        $errno          = 0;
        $errstr         = '';

        if ($this->debug) {
            call_user_func($this->debugHandler, "Connecting to $address...");
        }

        $stream = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            $connectTimeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($stream === false) {
            if ($this->debug) {
                call_user_func($this->debugHandler, "Connection to $address failed: $errstr ($errno)");
            }
            return false;
        }

        stream_set_blocking($stream, true);
        $this->applyTimeout($stream, $this->recvTimeoutMs);

        if ($this->debug) {
            call_user_func($this->debugHandler, "Connected to $address!");
        }

        return $stream;
    }

    /** Apply a millisecond receive timeout to a stream via stream_set_timeout(). */
    private function applyTimeout(mixed $stream, int $ms): void
    {
        stream_set_timeout($stream, (int) floor($ms / 1000), ($ms % 1000) * 1000);
    }

    /**
     * Convert milliseconds to a [sec, usec] pair suitable for stream_select().
     *
     * @return array{int, int}
     */
    private function msToSelectArgs(int $ms): array
    {
        return [(int) floor($ms / 1000), ($ms % 1000) * 1000];
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

    /**
     * {@inheritdoc}
     *
     * The send timeout governs both the initial connect (rounded up to the nearest
     * second) and the stream_select() wait inside write(). It does not affect
     * fread() – use setRecvTimeout() for that.
     */
    public function setSendTimeout(int $timeout): bool
    {
        $this->sendTimeoutMs = $timeout;
        return true;
    }

    /**
     * {@inheritdoc}
     *
     * Updates the internal value used by stream_select() in readAll() and –
     * when the stream is already open – the live stream_set_timeout() on the stream.
     */
    public function setRecvTimeout(int $timeout): bool
    {
        $this->recvTimeoutMs = $timeout;
        if ($this->stream !== null && is_resource($this->stream)) {
            $this->applyTimeout($this->stream, $timeout);
        }
        return true;
    }

    /**
     * {@inheritdoc}
     *
     * Controls the 'verify_peer' and 'verify_peer_name' SSL context options.
     * Takes effect on the next call to open(); does not affect an already-open connection.
     *
     * Set to false only when the SMSC uses a self-signed certificate in a
     * trusted / private network environment.
     */
    public function setSslVerification(bool $verify): void
    {
        $this->verifySsl = $verify;
    }
}

