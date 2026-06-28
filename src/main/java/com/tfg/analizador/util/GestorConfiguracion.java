package com.tfg.analizador.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Gestiona la carga de la configuración externa del sistema.
 * Implementa el patrón Singleton para garantizar una única lectura
 * del archivo {@code config.properties} durante todo el ciclo de vida
 * de la aplicación, evitando accesos redundantes al sistema de archivos.
 */
public class GestorConfiguracion {

    private static final String RUTA_CONFIG = "config.properties";
    private static GestorConfiguracion instancia;
    private final Properties propiedades;

    /**
     * Constructor privado. Lee el archivo de configuración externo
     * y carga todas las propiedades en memoria.
     *
     * @throws IOException si el archivo {@code config.properties} no existe
     *                     o no se puede leer.
     */
    private GestorConfiguracion() throws IOException {
        propiedades = new Properties();
        try (FileInputStream fis = new FileInputStream(RUTA_CONFIG)) {
            propiedades.load(fis);
        }
    }

    /**
     * Devuelve la instancia única del gestor de configuración.
     * Si es la primera invocación, carga el archivo de propiedades.
     *
     * @return la instancia Singleton de {@code GestorConfiguracion}.
     * @throws IOException si no se encuentra el archivo de configuración.
     */
    public static synchronized GestorConfiguracion getInstancia() throws IOException {
        if (instancia == null) {
            instancia = new GestorConfiguracion();
        }
        return instancia;
    }

    /**
     * Obtiene el valor de una propiedad por su clave.
     *
     * @param clave la clave de la propiedad (p. ej. {@code "mail.remitente"}).
     * @return el valor asociado a la clave, o {@code null} si no existe.
     */
    public String getPropiedad(String clave) {
        return propiedades.getProperty(clave);
    }
}
