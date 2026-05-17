package com.tfg.analizador.presentacion;

import com.tfg.analizador.logica.GestorUsuarios;
import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;

public class ControladorRegistro {

    @FXML
    private TextField txtEmail;

    @FXML
    private PasswordField txtPass;

    @FXML
    private PasswordField txtConfirmarPass;

    @FXML
    private Button btnRegistrar;

    @FXML
    private Label lblError;

    @FXML
    void handleRegistrarAction(ActionEvent event) {
        // Limpia los errores anteriores
        lblError.setText("");
        lblError.getStyleClass().remove("mensaje-exito");
        if (!lblError.getStyleClass().contains("mensaje-error")) {
            lblError.getStyleClass().add("mensaje-error");
        }

        // Tomamos los datos
        String email = txtEmail.getText().trim();
        String pass = txtPass.getText();
        String passConf = txtConfirmarPass.getText();

        // Error para cuando hay campos vacios
        if (email.isEmpty() || pass.isEmpty() || passConf.isEmpty()) {
            lblError.setText("Todos los campos son obligatorios");
            return;
        }

        //Error para cuando el formato del email no es correcto
        String regexEmail = "^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$";
        if (!email.matches(regexEmail)) {
            lblError.setText("El formato de email es incorrecto");
            return;
        }

        // Error de diferentes contraseñas
        if (!pass.equals(passConf)) {
            lblError.setText("Las contraseñas no coinciden");
            return;
        }

        // Delegamos TODA la lógica de negocio a la capa correspondiente
        try {
            GestorUsuarios logicaUsuarios = new GestorUsuarios();
            logicaUsuarios.registrarNuevoUsuario(email, pass);

            // Si no hay excepciones, el registro fue un éxito
            lblError.getStyleClass().remove("mensaje-error");
            lblError.getStyleClass().add("mensaje-exito");
            lblError.setText("¡Cuenta creada con éxito!");

            txtEmail.clear();
            txtPass.clear();
            txtConfirmarPass.clear();

        } catch (Exception e) {
            // Capturamos el mensaje traducido desde la capa lógica y lo mostramos
            lblError.getStyleClass().remove("mensaje-exito");
            lblError.getStyleClass().add("mensaje-error");
            lblError.setText(e.getMessage());
        }
    }

    @FXML
    void handleVolverLogin(MouseEvent event) {
        GestorVistas.irALogin();
    }
}