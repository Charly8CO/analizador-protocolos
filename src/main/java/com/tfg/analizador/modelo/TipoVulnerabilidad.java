package com.tfg.analizador.modelo;

/**
 * Enum centralizado que define los tipos de vulnerabilidad detectables por el
 * motor.
 * Evita el uso de cadenas hardcodeadas dispersas en el código (Magic Strings).
 */
public enum TipoVulnerabilidad {

    FALTA_FRESCURA("Falta de Frescura en Clave (Replay Attack)"),
    REFLEXION("Advertencia: Reflexión (Type Flaw)"),
    FALLO_DESAFIO_RESPUESTA("Fallo de Desafío-Respuesta"),
    ADVERTENCIA_DESAFIO_RESPUESTA("Advertencia Estructural (Falta de Desafío-Respuesta)"),
    AUTENTICACION_UNILATERAL("Advertencia: Autenticación Unilateral (Falta de Confirmación)"),
    SPOOFING("Suplantación de Identidad (Spoofing)"),
    FALLO_ACCESIBILIDAD("Fallo de Accesibilidad (Clave Inaccesible)");

    private final String descripcion;

    TipoVulnerabilidad(String descripcion) {
        this.descripcion = descripcion;
    }

    public String getDescripcion() {
        return descripcion;
    }
}
