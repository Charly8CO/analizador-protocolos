package com.tfg.analizador.presentacion;

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.logica.GestorUsuarios;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.util.GestorVistas;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
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

    @FXML
    private Label lblError;

    //Metodos que harán los botones
    @FXML
    void handleConfirmarAction(ActionEvent event) {

        // Limpia los errores anteriores
        lblError.setText("");
        lblError.getStyleClass().remove("mensaje-exito");
        if (!lblError.getStyleClass().contains("mensaje-error")) {
            lblError.getStyleClass().add("mensaje-error");
        }

        // Tomamos los datos
        String email = txtUsuario.getText().trim();
        String pass = txtPass.getText();

        // Error para cuando hay campos vacios
        if (email.isEmpty() || pass.isEmpty()) {
            lblError.setText("Todos los campos son obligatorios");
            return;
        }

        try {
            GestorUsuarios logicaUsuarios = new GestorUsuarios();
            Usuario usAutenticado = logicaUsuarios.autenticarUsuario(email, pass);

            // Guardamos el usuario de la sesión activa
            GestorSesion.getInstancia().iniciarSesion(usAutenticado);

            // Si no hay excepciones, se inició sesión correctamente
            lblError.getStyleClass().remove("mensaje-error");
            lblError.getStyleClass().add("mensaje-exito");
            lblError.setText("¡Bienveido, " + usAutenticado.getNombreUsuario() + "!");
            
            // Damos paso a la vista del dashboard
            GestorVistas.irADashB();

            txtUsuario.clear();
            txtPass.clear();

        } catch (Exception e) {
            // Capturamos el mensaje traducido desde la capa lógica y lo mostramos
            lblError.getStyleClass().remove("mensaje-exito");
            lblError.getStyleClass().add("mensaje-error");
            lblError.setText(e.getMessage());
        }
    }

    //mandar a la pestaña de registro
    @FXML
    void handleRegistrarAction(ActionEvent event) throws Exception{

        GestorVistas.irARegistro();

    }
}