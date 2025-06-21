<?php
class Logger {
    private $logFile;
    
    public function __construct($logFile = 'api.log') {
        $this->logFile = $logFile;
    }
    
    public function info($message) {
        $this->log('INFO', $message);
    }
    
    public function warning($message) {
        $this->log('WARNING', $message);
    }
    
    public function error($message) {
        $this->log('ERROR', $message);
    }
    
    public function debug($message) {
        $this->log('DEBUG', $message);
    }
    
    private function log($level, $message) {
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = "[$timestamp] [$level] $message" . PHP_EOL;
        
        // Write to file
        file_put_contents($this->logFile, $logEntry, FILE_APPEND | LOCK_EX);
        
        // Also output to console for development
        if (php_sapi_name() === 'cli') {
            echo $logEntry;
        }
    }
}
?> 