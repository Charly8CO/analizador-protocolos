package com.tfg.analizador.logica;

import java.io.File;
import java.nio.file.Files;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.persistencia.GestorBBDD;

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
           
            // Insertamos el registro sin los nullables
            boolean exito = GestorBBDD.insertarProtocolo(
                usuarioActivo.getIdUsuario(), 
                archivo.getName(), 
                archivo.getAbsolutePath()
            );

            if (!exito) {
                throw new Exception("El archivo se guardó en el disco local, pero hubo un error al registrarlo en el historial de la base de datos.");
            } else {
                System.out.println("Registrando en SQLite: " + archivo.getName() + " para el usuario " + usuarioActivo.getNombreUsuario());
            }
        }
    }
    
}