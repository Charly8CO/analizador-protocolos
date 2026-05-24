package com.tfg.analizador.presentacion;

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.modelo.Usuario;

import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;

public class ControladorPrincipal {

    //El uso de TableView nos permitirá mostrar listas de datos sin problema alguno
    @FXML
    private TableView<?> tablaProtocolos;

    @FXML
    private TableColumn<?, ?> colNombre;

    @FXML
    private TableColumn<?, ?> colAcciones;

    @FXML
    public void initialize() {
        Usuario usuario = GestorSesion.getInstancia().getUsuarioActivo();
        
        if (usuario != null) {
            System.out.println("Panel de Control cargado para: " + usuario.getNombreUsuario());
        }
    }
}