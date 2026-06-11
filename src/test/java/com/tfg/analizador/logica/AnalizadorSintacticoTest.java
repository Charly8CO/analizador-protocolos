package com.tfg.analizador.logica;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tfg.analizador.modelo.Agente;
import com.tfg.analizador.modelo.Cifrado;
import com.tfg.analizador.modelo.Clave;
import com.tfg.analizador.modelo.ElementoMensaje;
import com.tfg.analizador.modelo.Nonce;

public class AnalizadorSintacticoTest {

    private AnalizadorSintactico sintactico;
    private Agente creadorSimulado;

    @BeforeEach
    void setUp() {
        sintactico = new AnalizadorSintactico();
        creadorSimulado = new Agente("Alice");
    }

    @Test
    void testParseoNoncesYClaves() {
        String contenido = "Na, K_ab";
        List<ElementoMensaje> ast = sintactico.parsearContenido(contenido, creadorSimulado);
        
        assertEquals(2, ast.size(), "Debería separar dos elementos por la coma.");
        assertTrue(ast.get(0) instanceof Nonce, "Na debe ser reconocido como Nonce.");
        assertTrue(ast.get(1) instanceof Clave, "K_ab debe ser reconocido como Clave.");
        
        // Comprobación de tu interfaz ElementoMensaje
        assertEquals("Na", ast.get(0).getIdentificador());
    }

    @Test
    void testParseoCompositeCifradoAnidado() {
        // Un bloque cifrado dentro de otro bloque cifrado.
        String contenido = "{TextoPlano, {Na}K2}K1";
        List<ElementoMensaje> ast = sintactico.parsearContenido(contenido, creadorSimulado);
        
        assertEquals(1, ast.size(), "La raíz es un único gran bloque cifrado.");
        assertTrue(ast.get(0) instanceof Cifrado);
        
        Cifrado nivel1 = (Cifrado) ast.get(0);
        assertEquals("K1", nivel1.getClaveSello().getIdentificador());
        assertEquals(2, nivel1.getContenido().size(), "El bloque exterior contiene 2 elementos.");
        
        // Verifica que el segundo elemento de ese bloque es a su vez OTRO bloque cifrado.
        assertTrue(nivel1.getContenido().get(1) instanceof Cifrado);
        Cifrado nivel2 = (Cifrado) nivel1.getContenido().get(1);
        assertEquals("K2", nivel2.getClaveSello().getIdentificador());
    }
}