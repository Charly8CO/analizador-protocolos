package com.tfg.analizador.logica;

/**
 * Excepción base del proyecto Analizador de Protocolos.
 * Extiende RuntimeException para ser una excepción no verificada (unchecked),
 * manteniendo la misma semántica de lanzamiento que IllegalArgumentException
 * sin obligar a declarar throws en todas las firmas de método.
 */
public class AnalizadorException extends RuntimeException {
    public AnalizadorException(String mensaje) {
        super(mensaje);
    }

    public AnalizadorException(String mensaje, Throwable causa) {
        super(mensaje, causa);
    }
}
