<?php

namespace smpp\transport;

/**
 * Common interface for all SMPP transports.
 * Implementations include plain-TCP (Socket) and SSL/TLS-capable (StreamSocket) transports.
 */
interface TransportInterface
{
    /**
     * Open the connection, trying each configured host in succession.
     * Throws SocketTransportException when no host can be reached.
     *
     * @throws \smpp\exceptions\SocketTransportException
     */
    public function open(): void;

    /**
     * Cleanly shut down the connection.
     */
    public function close(): void;

    /**
     * Check whether the connection is currently open.
     *
     * @return bool
     * @throws \smpp\exceptions\SocketTransportException
     */
    public function isOpen(): bool;

    /**
     * Check whether data is waiting to be read without blocking.
     *
     * @return bool
     * @throws \smpp\exceptions\SocketTransportException
     */
    public function hasData(): bool;

    /**
     * Read up to $length bytes from the connection.
     * Returns false on EOF or timeout.
     *
     * @param int $length
     * @return string|false
     * @throws \smpp\exceptions\SocketTransportException
     */
    public function read(int $length): string|false;

    /**
     * Read exactly $length bytes, blocking until all bytes arrive.
     * Throws SocketTransportException on timeout or connection failure.
     *
     * @param int $length
     * @return string
     * @throws \smpp\exceptions\SocketTransportException
     */
    public function readAll(int $length): string;

    /**
     * Write all $length bytes of $buffer to the connection.
     * Throws SocketTransportException on timeout or connection failure.
     *
     * @param string $buffer
     * @param int    $length
     * @throws \smpp\exceptions\SocketTransportException
     */
    public function write(string $buffer, int $length): void;

    /**
     * Set the send timeout in milliseconds.
     * If called before open(), the value is stored as the default for the next connection.
     *
     * @param int $timeout Timeout in milliseconds
     * @return bool
     */
    public function setSendTimeout(int $timeout): bool;

    /**
     * Set the receive timeout in milliseconds.
     * If called before open(), the value is stored as the default for the next connection.
     *
     * @param int $timeout Timeout in milliseconds
     * @return bool
     */
    public function setRecvTimeout(int $timeout): bool;

    /**
     * Enable or disable SSL/TLS peer certificate verification.
     *
     * When $verify is true (the default) both the certificate chain and the hostname
     * are verified against the system CA bundle (or the cafile/capath option when set).
     * Set to false only for self-signed certificates in trusted environments.
     *
     * For plain-TCP transports this method is a no-op.
     *
     * @param bool $verify true = verify (recommended); false = skip verification
     */
    public function setSslVerification(bool $verify): void;
}

