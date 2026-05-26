package com.tfg.analizador.util;

import java.io.IOException;
import java.net.URL;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class GestorVistas {

    private static Stage escenarioPrincipal;

    public enum TipoPantalla { LOGIN, REGISTRO, DASHBOARD, ANALIZADOR, DESCONOCIDA }
    private static TipoPantalla pantallaActual = TipoPantalla.DESCONOCIDA;

    public static TipoPantalla getPantallaActual() {
        return pantallaActual;
    }

    // Lo llamo solo en App una vez
    public static void setEscenarioPrincipal(Stage stage) {
        escenarioPrincipal = stage;
    }

    public static void irALogin() {
        pantallaActual = TipoPantalla.LOGIN;
        cambiarEscena("/com/tfg/analizador/VistaLogin.fxml", "TFG - Iniciar Sesión");
    }

    public static void irARegistro() {
        pantallaActual = TipoPantalla.REGISTRO;
        cambiarEscena("/com/tfg/analizador/VistaRegistro.fxml", "TFG - Registrar cuenta");
    }

    public static void irADashB(){
        pantallaActual = TipoPantalla.DASHBOARD;
        cambiarEscena("/com/tfg/analizador/VistaDashBoard.fxml", "TFG - DashBoard");
    }

    public static void irAAnalizador() {
        pantallaActual = TipoPantalla.ANALIZADOR;
        cambiarEscena("/com/tfg/analizador/VistaAnalizador.fxml", "TFG - Analizador de Protocolos (Editor)");
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
            // Leer el diseño
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