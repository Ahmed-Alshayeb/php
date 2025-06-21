<?php
class JWT {
    public static function encode($payload, $secret, $algorithm = 'HS256') {
        $header = json_encode(['typ' => 'JWT', 'alg' => $algorithm]);
        $payload = json_encode($payload);
        
        $base64Header = self::base64url_encode($header);
        $base64Payload = self::base64url_encode($payload);
        
        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $secret, true);
        $base64Signature = self::base64url_encode($signature);
        
        return $base64Header . "." . $base64Payload . "." . $base64Signature;
    }
    
    public static function decode($token, $secret, $algorithms = ['HS256']) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception('Invalid token format');
        }
        
        list($header, $payload, $signature) = $parts;
        
        $decodedHeader = json_decode(self::base64url_decode($header), true);
        if (!$decodedHeader || !in_array($decodedHeader['alg'], $algorithms)) {
            throw new Exception('Invalid algorithm');
        }
        
        $expectedSignature = hash_hmac('sha256', $header . "." . $payload, $secret, true);
        $expectedSignature = self::base64url_encode($expectedSignature);
        
        if (!hash_equals($signature, $expectedSignature)) {
            throw new Exception('Invalid signature');
        }
        
        $decodedPayload = json_decode(self::base64url_decode($payload), true);
        if (!$decodedPayload) {
            throw new Exception('Invalid payload');
        }
        
        return $decodedPayload;
    }
    
    private static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    private static function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }
}
?> 