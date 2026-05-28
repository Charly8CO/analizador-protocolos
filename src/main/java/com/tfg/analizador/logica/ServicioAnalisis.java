package com.tfg.analizador.logica;

import com.tfg.analizador.modelo.Protocolo;

public class ServicioAnalisis {
    
    public Protocolo procesarNuevoProtocolo(String textoPlano) throws Exception {
        AnalizadorLexico analizador = new AnalizadorLexico();
        MotorAnalisis motor = new MotorAnalisis();
        
        // Validar y compilar
        Protocolo p = analizador.compilarProtocolo("Protocolo_Temporal", textoPlano);
        
        // Analizar vulnerabilidades 
        // motor.evaluarDesafioRespuesta(p);
        
        return p;
    }
}