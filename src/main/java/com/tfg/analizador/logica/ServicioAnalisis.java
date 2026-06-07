package com.tfg.analizador.logica;

import java.io.File;
import java.nio.file.Files;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;

public class ServicioAnalisis {
    
    public boolean validarSintaxisSolo(String textoPlano) throws Exception {
        AnalizadorLexico analizador = new AnalizadorLexico();
        return analizador.analizarSintaxis(textoPlano);
    }

    public Protocolo procesarNuevoProtocolo(String textoPlano) throws Exception {
        AnalizadorLexico analizador = new AnalizadorLexico();
        MotorAnalisis motor = new MotorAnalisis();
        
        // Compilación 
        Protocolo p = analizador.compilarProtocolo("Análisis_Actual", textoPlano);
        
        // Analizar
        motor.analizarEsSeguro(p);
        
        return p;
    }

    public void guardarProtocolo(File archivo, String contenido) throws Exception {
        // Guardado en local
        Files.writeString(archivo.toPath(), contenido);

        // Registro en la base de datos 
        // Obtenemos el usuario de la sesión actual
        Usuario usuarioActivo = GestorSesion.getInstancia().getUsuarioActivo();
        
        if (usuarioActivo != null) {
            // Simulamos el guardado en BBDD (esto conectará con tu GestorBBDD próximamente)
            System.out.println("Registrando en SQLite: " + archivo.getName() + " para el usuario " + usuarioActivo.getNombreUsuario());
            
            // Aquí iría: GestorBBDD.insertarProtocolo(usuarioActivo.getId(), archivo.getName(), archivo.getAbsolutePath());
        }
    }
    
}