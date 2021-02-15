<?php

namespace abdelrhman\jwtpkg;

class jwt {

    private array   $header,
                    $payload;

    private string  $secret,

                    $jsonHeader,
                    $jsonPayload,

                    $base64_header,
                    $base64_payload,

                    $signature,
                    
                    $token;
    

    public function setHeader(string $alg = "HS256", string $tokenTyp = "JWT"): self {

        $this->header = [

            "typ" => $tokenTyp,
            "alg" => $alg
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


    private function formJsonAsBase64Encode(): self {

        $this->base64_header = $this->sanitize(

            base64_encode($this->jsonHeader)
        );
            
        $this->base64_payload = $this->sanitize(

            base64_encode($this->jsonPayload)
        );

        return $this;
    }

    private function sanitize(string $base64): string {

        return str_replace( [ '+', '/', '=' ], [ '-', '_', '' ], $base64 );

    }


    public function generateSignature(): self {

        $this->signature = hash_hmac(

            "sha256",

            $this->base64_header .".". $this->base64_payload,

            $this->secret,

            true

        );

        $this->signature = $this->sanitize(
            base64_encode($this->signature)
        );


        return $this;
    }

    public function generateToken(): self {

        $this->formTokenAsJson()
            ->formJsonAsBase64Encode()
            ->generateSignature();
        
        $this->token = $this->base64_header . "." . $this->base64_payload . "."
            . $this->signature;

        return $this;
    }

    public function getToken(): string {
        return $this->token;
    }

    public function getTokenComponenets(): array {
        return explode(".", $this->token);
    }

    public function printTokenComponenets(): void {
        
        print_r($this->getTokenComponenets());

    }
}