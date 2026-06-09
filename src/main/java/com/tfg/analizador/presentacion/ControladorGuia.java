package com.tfg.analizador.presentacion;

import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;

public class ControladorGuia {

    @FXML
    void handleVolver(ActionEvent event) {
        // Leemos el historial: ¿Dónde estábamos antes de abrir la guía?
        GestorVistas.TipoPantalla anterior = GestorVistas.getPantallaAnterior();

        if (anterior == GestorVistas.TipoPantalla.ANALIZADOR) {
            GestorVistas.irAAnalizador();
        } else if (anterior == GestorVistas.TipoPantalla.PERFIL) {
            GestorVistas.irAPerfil();
        } else {
            // Por defecto y como medida de seguridad, volvemos al Dashboard
            GestorVistas.irADashB();
        }
    }
}