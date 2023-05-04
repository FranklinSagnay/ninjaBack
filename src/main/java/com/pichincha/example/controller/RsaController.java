package com.pichincha.example.controller;

import com.pichincha.example.util.RsaUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static com.pichincha.example.util.RsaUtil.generateKeyPair;
@RestController
public class RsaController {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private final RsaUtil rsaUtil;

    @Autowired
    public RsaController(RsaUtil rsaUtil) {
        this.rsaUtil = rsaUtil;
        try {
            KeyPair keyPair = generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            // Manejar errores
        }
    }


    @PostMapping("/rsaencrypt")
    public ResponseEntity<Map<String, String>> encryptData(@RequestBody String data) {
        try {
            String encryptedData = rsaUtil.encrypt(data, publicKey);

            // Crear un mapa para almacenar el mensaje encriptado y la clave privada
            Map<String, String> response = new HashMap<>();
            response.put("encryptedData", encryptedData);
            response.put("privateKey", privateKeyToString(privateKey));

            // Devolver la respuesta con el mensaje encriptado y la clave privada
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            // Manejar errores
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @PostMapping("/rsadecrypt")
    public String decryptData(@RequestBody Map<String, String> request) {
        try {
            String encryptedData = request.get("encryptedData");
            String privateKeyStr = request.get("privateKey");

            PrivateKey privateKey = stringToPrivateKey(privateKeyStr);
            String decryptedData = rsaUtil.decrypt(encryptedData, privateKey);

            return decryptedData;
        } catch (Exception e) {
            // Manejar errores
            return "Error al desencriptar los datos";
        }
    }

    private PrivateKey stringToPrivateKey(String privateKeyStr) throws Exception {
        // Decodificar la clave privada desde Base64
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyStr);

        // Crear la especificación de clave privada PKCS8
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        // Obtener la instancia del algoritmo de cifrado RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generar la clave privada a partir de la especificación
        return keyFactory.generatePrivate(keySpec);
    }

    private String privateKeyToString(PrivateKey privateKey) {
        // Obtener los bytes de la clave privada
        byte[] privateKeyBytes = privateKey.getEncoded();

        // Codificar la clave privada a Base64
        return Base64.getEncoder().encodeToString(privateKeyBytes);
    }

}
