package com.pichincha.example.controller;

import com.pichincha.example.util.AesUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AesController {

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody String data) {
        try {
            return AesUtil.encrypt(data);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error al encriptar los datos";
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody String encryptedData) {
        try {
            return AesUtil.decrypt(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error al desencriptar los datos";
        }
    }
}