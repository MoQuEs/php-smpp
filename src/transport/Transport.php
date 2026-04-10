<?php

namespace smpp\transport;

abstract class Transport implements TransportInterface
{
    /** @var array Resolved host pool: [hostname, port, ip6s[], ip4s[]] */
    protected array $hosts = [];

    public bool $debug;

    /** @var callable */
    protected $debugHandler;

    /** @var string Connection scheme: 'tcp', 'ssl' or 'tls' */
    protected string $scheme = 'tcp';

    /** @var array Extra SSL context options */
    protected array $sslOptions = [];

    /** @var bool Verify peer certificate and hostname for SSL/TLS */
    protected bool $verifySsl = true;

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
     * @param array         $sslOptions   Additional SSL context options (cafile, local_cert, ...)
     * @param callable|null $debugHandler Callback for debug messages; defaults to error_log
     */
    public function __construct(
        array $hosts,
        array|int $ports,
        string $scheme = 'tcp',
        array $sslOptions = [],
        mixed $debugHandler = null
    ) {
        $this->initTransport($hosts, $ports, $scheme, $sslOptions, $debugHandler);
    }

    /**
     * Initialize common transport config shared by all implementations.
     */
    protected function initTransport(
        array $hosts,
        array|int $ports,
        string $scheme = 'tcp',
        array $sslOptions = [],
        mixed $debugHandler = null
    ): void {
        if (!in_array($scheme, ['tcp', 'ssl', 'tls'], true)) {
            throw new \InvalidArgumentException("Scheme must be 'tcp', 'ssl' or 'tls', got: '$scheme'");
        }

        $this->scheme        = $scheme;
        $this->sslOptions    = $sslOptions;
        $this->debug         = self::$defaultDebug;
        $this->debugHandler  = $debugHandler ?? 'error_log';
        $this->sendTimeoutMs = self::$defaultSendTimeout;
        $this->recvTimeoutMs = self::$defaultRecvTimeout;

        $resolved = [];
        foreach ($hosts as $key => $host) {
            $resolved[] = [$host, is_array($ports) ? $ports[$key] : $ports];
        }
        if (self::$randomHost) {
            shuffle($resolved);
        }

        $this->hosts = [];
        $this->resolveHosts($resolved);
    }

    /**
     * Convert milliseconds to [sec, usec] pair.
     *
     * @return array{int, int}
     */
    protected function msToSelectArgs(int $ms): array
    {
        return [(int) floor($ms / 1000), ($ms % 1000) * 1000];
    }

    /**
     * Convert milliseconds to socket timeout array.
     *
     * @return array{sec:int, usec:int}
     */
    protected function msToSocketTimeout(int $ms): array
    {
        $usec = $ms * 1000;
        return ['sec' => (int) floor($usec / 1000000), 'usec' => $usec % 1000000];
    }

    /** Apply a receive timeout to an open stream resource. */
    protected function applyStreamTimeout(mixed $stream, int $ms): void
    {
        stream_set_timeout($stream, (int) floor($ms / 1000), ($ms % 1000) * 1000);
    }

    /** Build stream SSL context using common SSL options and verification flags. */
    protected function buildStreamContext(string $hostname): mixed
    {
        if ($this->scheme === 'tcp') {
            return stream_context_create([]);
        }

        $ssl = array_merge(
            ['peer_name' => $hostname],
            $this->sslOptions,
            [
                'verify_peer'      => $this->verifySsl,
                'verify_peer_name' => $this->verifySsl,
            ]
        );

        return stream_context_create(['ssl' => $ssl]);
    }

    /** Lightweight debug logger used by both backends. */
    protected function logDebug(string $message): void
    {
        if ($this->debug) {
            call_user_func($this->debugHandler, $message);
        }
    }

    public function setSendTimeout(int $timeout): bool
    {
        $this->sendTimeoutMs = $timeout;
        return true;
    }

    public function setRecvTimeout(int $timeout): bool
    {
        $this->recvTimeoutMs = $timeout;
        $this->onRecvTimeoutChanged($timeout);
        return true;
    }

    /** Hook for transports that can apply recv timeout on an already-open connection. */
    protected function onRecvTimeoutChanged(int $timeout): void
    {
        // no-op by default
    }

    public function setSslVerification(bool $verify): void
    {
        $this->verifySsl = $verify;
    }

    /**
     * Resolve hostnames into IPs and sort them into IPv4 / IPv6 buckets.
     *
     * @param array $hosts Raw [$hostname, $port] pairs
     * @throws \InvalidArgumentException when no valid address can be found
     */
    protected function resolveHosts(array $hosts): void
    {
        $totalIps = 0;

        foreach ($hosts as [$hostname, $port]) {
            $ip4s = [];
            $ip6s = [];

            if (preg_match('/^([12]?[0-9]?[0-9]\.){3}([12]?[0-9]?[0-9])$/', $hostname)) {
                $ip4s[] = $hostname;
            } elseif (preg_match('/^([0-9a-f:]+):[0-9a-f]{1,4}$/i', $hostname)) {
                $ip6s[] = $hostname;
            } else {
                if (!self::$forceIpv4) {
                    $records = dns_get_record($hostname, DNS_AAAA);
                    if ($records === false && $this->debug) {
                        call_user_func($this->debugHandler, 'DNS lookup for AAAA records for: ' . $hostname . ' failed');
                    }
                    if ($records) {
                        foreach ($records as $r) {
                            if (isset($r['ipv6']) && $r['ipv6']) {
                                $ip6s[] = $r['ipv6'];
                            }
                        }
                    }
                    if ($this->debug) {
                        call_user_func($this->debugHandler, "IPv6 addresses for $hostname: " . implode(', ', $ip6s));
                    }
                }
                if (!self::$forceIpv6) {
                    $records = dns_get_record($hostname, DNS_A);
                    if ($records === false && $this->debug) {
                        call_user_func($this->debugHandler, 'DNS lookup for A records for: ' . $hostname . ' failed');
                    }
                    if ($records) {
                        foreach ($records as $r) {
                            if (isset($r['ip']) && $r['ip']) {
                                $ip4s[] = $r['ip'];
                            }
                        }
                    }
                    $ip = gethostbyname($hostname);
                    if ($ip !== $hostname && !in_array($ip, $ip4s, true)) {
                        $ip4s[] = $ip;
                    }
                    if ($this->debug) {
                        call_user_func($this->debugHandler, "IPv4 addresses for $hostname: " . implode(', ', $ip4s));
                    }
                }
            }

            if (
                (self::$forceIpv4 && empty($ip4s))
                || (self::$forceIpv6 && empty($ip6s))
                || (empty($ip4s) && empty($ip6s))
            ) {
                continue;
            }

            $totalIps += count($ip4s) + count($ip6s);
            $this->hosts[] = [$hostname, $port, $ip6s, $ip4s];
        }

        if ($this->debug) {
            call_user_func(
                $this->debugHandler,
                'Built connection pool of ' . count($this->hosts) . ' host(s) with ' . $totalIps . ' ip(s) in total'
            );
        }

        if (empty($this->hosts)) {
            throw new \InvalidArgumentException('No valid hosts was found');
        }
    }
}

