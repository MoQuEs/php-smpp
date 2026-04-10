<?php

namespace smpp\transport;

abstract class Transport implements TransportInterface
{
    /** @var array Resolved host pool: [hostname, port, ip6s[], ip4s[]] */
    protected array $hosts = [];

    public bool $debug;

    /** @var callable */
    protected $debugHandler;

    public static bool $forceIpv6  = false;
    public static bool $forceIpv4  = false;

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

