package com.snehil.cloudflare.okhttp.exceptions

/**
 * Exception thrown by [com.snehil.cloudflare.okhttp.CloudflareHTTPClient] when the page has an unsupported challenge.
 * Es: captcha challenge
 */
class UnsupportedChallengeException : Exception()