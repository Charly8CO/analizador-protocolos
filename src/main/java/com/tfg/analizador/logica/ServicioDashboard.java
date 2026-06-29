package com.tfg.analizador.logica;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.persistencia.GestorBBDD;

/**
 * Capa de servicio intermedia entre la presentación (ControladorPrincipal) y la
 * persistencia.
 */
public class ServicioDashboard {

    private final GestorBBDD gestorBD = new GestorBBDD();

    public List<Protocolo> cargarProtocolos(int idUsuario) {
        return gestorBD.cargarProtocolos(idUsuario);
    }

    public int obtenerTotalProtocolosSeguros(int idUsuario) {
        return gestorBD.obtenerTotalProtocolosSeguros(idUsuario);
    }

    public int obtenerTotalVulnerabilidades(int idUsuario) {
        return gestorBD.obtenerTotalVulnerabilidades(idUsuario);
    }

    public Map<String, Integer> obtenerDistribucionVulnerabilidades(int idUsuario) {
        return gestorBD.obtenerDistribucionVulnerabilidades(idUsuario);
    }

    public boolean renombrarProtocolo(int idProtocolo, String nuevoNombre, String nuevaRuta) {
        return gestorBD.renombrarProtocolo(idProtocolo, nuevoNombre, nuevaRuta);
    }

    public boolean eliminarProtocolo(int idProtocolo) {
        return gestorBD.eliminarProtocolo(idProtocolo);
    }

    // Lee el contenido de un archivo de protocolo como texto plano.
    public String leerContenidoArchivo(File archivo) throws Exception {
        return Files.readString(archivo.toPath());
    }
}
