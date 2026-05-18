package com.tfg.analizador.util;

import java.io.IOException;
import java.net.URL;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class GestorVistas {

    private static Stage escenarioPrincipal;

    // Lo llamo solo en App una vez
    public static void setEscenarioPrincipal(Stage stage) {
        escenarioPrincipal = stage;
    }

    public static void irALogin() {
        cambiarEscena("/com/tfg/analizador/VistaLogin.fxml", "TFG - Iniciar Sesión");
    }

    public static void irARegistro() {
        cambiarEscena("/com/tfg/analizador/VistaRegistro.fxml", "TFG - Registrar cuenta");
    }

    public static void irADashB(){
        cambiarEscena("/com/tfg/analizador/VistaDashBoard.fxml", "TFG - DashBoard");
    }

    private static void cambiarEscena(String rutaFXML, String titulo) {
        
        if (escenarioPrincipal == null) {
            System.err.println("Error: El escenario principal no ha sido inicializado en GestorVistas.");
            return;
        }

        URL url = GestorVistas.class.getResource(rutaFXML);

          //Para evitar fallos desconocidos si no encuentra la ruta buscaremos la ruta y
          // comprobaremos que no sea nula si lo es se cierra el programa
        if (url == null) {
            System.err.println("Error crítico: No se encontró el archivo FXML en: " + rutaFXML);
            return;
        }

        try {
            //leer el diseño
            Parent base = FXMLLoader.load(url);

            //creamos una escena para poder mostrar el diseño
            Scene escena = new Scene(base);

            escenarioPrincipal.setTitle(titulo);
            escenarioPrincipal.setScene(escena);
        } catch (IOException e) {
            System.err.println("Error al cargar la vista: " + rutaFXML);
            e.printStackTrace();
        }
    }
}