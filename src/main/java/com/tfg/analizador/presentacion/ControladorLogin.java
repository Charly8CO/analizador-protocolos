package com.tfg.analizador.presentacion;

import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

public class ControladorLogin {

    @FXML
    private TextField txtUsuario;

    @FXML
    private PasswordField txtPass;

    @FXML
    private Button btnRegistrar;

    @FXML
    private Button btnConfirmar;

    //Metodos que harán los botones
    @FXML
    void handleConfirmarAction(ActionEvent event) {
        System.out.println("Clic en Confirmar");
    }

    //mandar a la pestaña de registro
    @FXML
    void handleRegistrarAction(ActionEvent event) throws Exception{

        GestorVistas.irARegistro();

    }
}