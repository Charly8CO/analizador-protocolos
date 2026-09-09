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

    @Test
    void testYahalomParalelo() {
        String spec = "Alice -> Bob : Alice, N_a\n" +
                      "Bob -> KDC : Bob, {Alice, N_a, N_b}K_bob_kdc\n" +
                      "KDC -> Alice : {Bob, K_ab, N_a, N_b}K_alice_kdc, {Alice, K_ab}K_bob_kdc\n" +
                      "Alice -> Bob : {Alice, K_ab}K_bob_kdc, {N_b}K_ab";
        Protocolo p = lexico.compilarProtocolo("Yahalom", spec);
        motor.analizarEsSeguro(p);
        
        System.out.println("Vulns en Yahalom: " + p.getVulnerabilidades().stream().map(v -> v.getTipoAtaque()).toList());
        assertTrue(p.isSeguro(), "Yahalom debe ser considerado seguro.");
    }

    @Test
    void testOtwayReesTypeFlaw() {
        String spec = "Alice -> Bob : I, Alice, Bob, {N_a, I, Alice, Bob}K_alice_kdc\n" +
                      "Bob -> KDC : I, Alice, Bob, {N_a, I, Alice, Bob}K_alice_kdc, {N_b, I, Alice, Bob}K_bob_kdc\n" +
                      "KDC -> Bob : I, {N_a, K_ab}K_alice_kdc, {N_b, K_ab}K_bob_kdc\n" +
                      "Bob -> Alice : I, {N_a, K_ab}K_alice_kdc";
        Protocolo p = lexico.compilarProtocolo("OtwayRees", spec);
        motor.analizarEsSeguro(p);
        
        assertTrue(p.isSeguro(), "Otway-Rees tiene un Type Flaw (Advertencia), por tanto isSeguro es true.");
        boolean typeFlawDetectado = p.getVulnerabilidades().stream()
                .anyMatch(v -> v.getTipoAtaque().toLowerCase().contains("reflexi") || 
                               v.getTipoAtaque().toLowerCase().contains("type flaw"));
        assertTrue(typeFlawDetectado, "Debe detectar el riesgo de reflexión (Type Flaw).");
    }

    @Test
    void testDesafioRespuestaAjena() {
        String spec = "Alice -> Bob : N_a\n" +
                      "Bob -> Alice : {N_a}K_mallory";
        Protocolo p = lexico.compilarProtocolo("DesafioFalso", spec);
        motor.analizarEsSeguro(p);
        
        assertFalse(p.isSeguro(), "Bob responde con una clave que Alice no conoce.");
        boolean desafioFallo = p.getVulnerabilidades().stream()
                .anyMatch(v -> v.getTipoAtaque().toLowerCase().contains("desafío") || 
                               v.getTipoAtaque().toLowerCase().contains("desafio"));
        assertTrue(desafioFallo, "Debe detectar el fallo de desafío-respuesta por clave ajena.");
    }

    @Test
    void testAutenticacionUnilateralEsAdvertencia() {
        String specPerfecto = "Alice -> KDC : Alice, Bob, T_1\n" +
                              "KDC -> Alice : {K_ab, T_1, {K_ab, T_1}K_bob_kdc}K_alice_kdc\n" +
                              "Alice -> Bob : {K_ab, T_1}K_bob_kdc\n" +
                              "Alice -> Bob : {Mensaje}K_ab";
        Protocolo pPerf = lexico.compilarProtocolo("AuthUnilateralPerf", specPerfecto);
        motor.analizarEsSeguro(pPerf);
        
        System.out.println("Vulns en AuthUnilateral: " + pPerf.getVulnerabilidades().stream().map(v -> v.getTipoAtaque()).toList());
        assertTrue(pPerf.isSeguro(), "El protocolo estructuralmente es seguro y la autenticación unilateral no lo invalida.");
        boolean advertenciaEncontrada = pPerf.getVulnerabilidades().stream()
                .anyMatch(v -> v.getTipoAtaque().toLowerCase().contains("unilateral") || 
                               v.getTipoAtaque().toLowerCase().contains("advertencia"));
        assertTrue(advertenciaEncontrada, "Debe existir una advertencia de autenticación unilateral.");
    }
}