package com.tfg.analizador.logica;

/**
 * Excepción base del proyecto Analizador de Protocolos.
 */
public class AnalizadorException extends Exception {
    public AnalizadorException(String mensaje) {
        super(mensaje);
    }

    public AnalizadorException(String mensaje, Throwable causa) {
        super(mensaje, causa);
    }
}
