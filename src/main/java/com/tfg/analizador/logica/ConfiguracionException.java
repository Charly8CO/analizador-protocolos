package com.tfg.analizador.logica;

/**
 * Excepción para errores de configuración del sistema.
 * Tipado específico para errores de configuración.
 */
public class ConfiguracionException extends AnalizadorException {
    public ConfiguracionException(String mensaje) {
        super(mensaje);
    }

    public ConfiguracionException(String mensaje, Throwable causa) {
        super(mensaje, causa);
    }
}
