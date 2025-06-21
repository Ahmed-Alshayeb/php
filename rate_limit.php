<?php
// Simple Rate Limiting
class RateLimiter {
    private $cacheFile;
    private $maxRequests;
    private $timeWindow;
    
    public function __construct($maxRequests = 100, $timeWindow = 3600) {
        $this->cacheFile = 'rate_limit_cache.json';
        $this->maxRequests = $maxRequests;
        $this->timeWindow = $timeWindow;
    }
    
    public function checkLimit($identifier) {
        $cache = $this->loadCache();
        $now = time();
        
        // Clean old entries
        $cache = array_filter($cache, function($entry) use ($now) {
            return $entry['timestamp'] > ($now - $this->timeWindow);
        });
        
        // Check if identifier exists
        if (isset($cache[$identifier])) {
            if ($cache[$identifier]['count'] >= $this->maxRequests) {
                return false; // Rate limit exceeded
            }
            $cache[$identifier]['count']++;
        } else {
            $cache[$identifier] = [
                'count' => 1,
                'timestamp' => $now
            ];
        }
        
        $this->saveCache($cache);
        return true;
    }
    
    private function loadCache() {
        if (file_exists($this->cacheFile)) {
            $content = file_get_contents($this->cacheFile);
            return json_decode($content, true) ?: [];
        }
        return [];
    }
    
    private function saveCache($cache) {
        file_put_contents($this->cacheFile, json_encode($cache));
    }
}

// Initialize rate limiter (disabled for development)
$rateLimiter = new RateLimiter(1000, 3600); // 1000 requests per hour

// For development, we'll skip rate limiting
// In production, you would check: if (!$rateLimiter->checkLimit($clientIP)) { http_response_code(429); exit; }
?> 