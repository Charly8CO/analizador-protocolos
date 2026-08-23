package com.tfg.analizador.logica;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tfg.analizador.modelo.Protocolo;

public class AnalizadorLexicoTest {

    private AnalizadorLexico lexico;

    @BeforeEach
    void setUp() {
        lexico = new AnalizadorLexico();
    }

    @Test
    void testCompilarProtocoloValido() {
        String spec = "Alice -> Bob : {Na}K_ab";
        Protocolo p = lexico.compilarProtocolo("ProtocoloValido", spec);

        // 1. Validar que el objeto Protocolo se instancia correctamente
        assertNotNull(p, "El protocolo compilado no debería ser nulo.");
        assertEquals("ProtocoloValido", p.getNombreProtocolo(), "El nombre del protocolo debe coincidir.");
        assertFalse(p.getMensajes().isEmpty(), "La lista de mensajes no debería estar vacía.");

        // 2. Validar que el analizador mapea bien los componentes básicos del mensaje
        assertEquals("Alice", p.getMensajes().get(0).getEmisor().getNombre(), "El emisor debe ser Alice.");
        assertEquals("Bob", p.getMensajes().get(0).getReceptor().getNombre(), "El receptor debe ser Bob.");
    }

    @Test
    void testRechazarSintaxisInvalida() {
        // Sintaxis rota (omisión del receptor obligatorios antes de los dos puntos)
        String specInvalida = "Alice -> : {Na}K_ab";

        // Verifica que tu analizador reacciona lanzando la excepción adecuada ante
        // cadenas corruptas
        assertThrows(AnalizadorException.class, () -> {
            lexico.compilarProtocolo("ProtocoloInvalido", specInvalida);
        }, "El analizador debería lanzar AnalizadorException ante una sintaxis rota.");
    }
}