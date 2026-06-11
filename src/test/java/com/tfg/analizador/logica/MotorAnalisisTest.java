package com.tfg.analizador.logica;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tfg.analizador.modelo.Protocolo;

public class MotorAnalisisTest {

    private AnalizadorLexico lexico;
    private MotorAnalisis motor;

    @BeforeEach
    void setUp() {
        lexico = new AnalizadorLexico();
        motor = new MotorAnalisis();
    }

    @Test
    void testDetectarFaltaDeFrescura() {
        // Trent distribuye K_ab a Alice sin incluir un Nonce generado por ella.
        String spec = "Trent -> Alice : {K_ab}K_at";
        Protocolo p = lexico.compilarProtocolo("PruebaFrescura", spec);
        
        motor.analizarEsSeguro(p);
        
        assertFalse(p.isSeguro(), "El protocolo debe marcarse como vulnerable.");
        
        // Búsqueda flexible que cubre tu nomenclatura exacta ("Desafío-Respuesta" o "Frescura")
        boolean detectado = p.getVulnerabilidades().stream()
                .anyMatch(v -> {
                    String ataque = v.getTipoAtaque().toLowerCase();
                    return ataque.contains("desafío") || 
                           ataque.contains("desafio") || 
                           ataque.contains("frescura");
                });
                
        assertTrue(detectado, "Debe registrarse la vulnerabilidad por falta de desafío o frescura.");
    }

    
    @Test
    void testDetectarRiesgoDeReflexion() {
        // Alice envía un desafío y Bob lo devuelve exactamente con la misma clave y estructura.
        String spec = "Alice -> Bob : {Na}K_ab\nBob -> Alice : {Na}K_ab";
        Protocolo p = lexico.compilarProtocolo("PruebaReflexion", spec);
        
        motor.analizarEsSeguro(p);
        
        // El motor detecta el peligro y marca el protocolo como inseguro
        assertFalse(p.isSeguro(), "El protocolo debe marcarse como vulnerable.");
        
        // Comprobación adaptada: tu motor clasifica la reflexión como Spoofing/Suplantación
        boolean detectado = p.getVulnerabilidades().stream()
                .anyMatch(v -> {
                    String ataque = v.getTipoAtaque().toLowerCase();
                    return ataque.contains("suplantación") || 
                           ataque.contains("suplantacion") || 
                           ataque.contains("spoofing") ||
                           ataque.contains("reflexion");
                });
                
        assertTrue(detectado, "Debe alertar de la suplantación por reflexión (Spoofing).");
    }
}