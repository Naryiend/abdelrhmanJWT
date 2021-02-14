<?php

namespace abdelrhman\jwtpkg;

class jwt {

    private array   $header,
                    $payload;

    private string  $secret,
                    $signature,

                    $jsonHeader,
                    $jsonPayload,

                    $base64_header,
                    $base64_payload,
                    
                    $token;
    

    public function __construct() {}

    public function setHeader(string $alg = "HS256", string $tokenTyp = "JWT"): self {

        $this->header = [

            "alg" => $alg,
            "typ" => $tokenTyp
        ];

        return $this;
    }

    public function setPayload(array $payload): self {

        $this->payload = $payload;
        return $this;
    }

    public function setSecrect(string $secret): self {

        $this->secret = $secret;
        return $this;
    }

    
    private function formTokenAsJson(): self {

        $this->jsonHeader = json_encode($this->header);
        $this->jsonPayload = json_encode($this->payload);

        return $this;
    }


    private function sanitize(string $base64): string {

        return str_replace( [ "+", "/", "=" ], [ "-", "_", "" ], $base64 );

    }

    private function formJsonAsBase64Encode(): self {

        $this->base64_header = $this->sanitize(
            base64_encode($this->jsonHeader) );
            
        $this->base64_payload = $this->sanitize(
            base64_encode($this->jsonPayload) );

        return $this;
    }


    public function generateSignature(bool $encryptSignature): self {

        $this->signature = hash_hmac(
            "sha256", $this->base64_header . $this->base64_payload, $this->secret, true
        );

        if ($encryptSignature)
        {
            $this->signature = $this->sanitize(
                base64_encode($this->signature));
        }

        return $this;
    }

    public function generateToken(bool $encryptSignature = false): void {

        $this->formTokenAsJson()
            ->formJsonAsBase64Encode()
            ->generateSignature($encryptSignature);

        $this->token = $this->base64_header . "." . $this->base64_payload . "."
            . $this->signature;

    }

    public function getToken(): string {
        return $this->token;
    }

    public function getTokenComponenets(): array {

        echo $this->token;
        preg_match_all(
            "/\.*\w+\.*/", $this->token, $componenets
        );

        return $componenets;
    }

    public function printTokenComponenets(): void {
        echo "<pre>";
        print_r($this->getTokenComponenets());
        echo "</pre>";
    }
}