package com.tfg.analizador.util;

import java.io.File;
import java.io.IOException;
import java.net.URL;

import com.tfg.analizador.presentacion.ControladorAnalisis;
import com.tfg.analizador.presentacion.ControladorMenu;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class GestorVistas {

    private static Stage escenarioPrincipal;

    public enum TipoPantalla { LOGIN, REGISTRO, DASHBOARD, ANALIZADOR, DESCONOCIDA, PERFIL, GUIA, RECUPERAR_PASS }
    private static TipoPantalla pantallaActual = TipoPantalla.DESCONOCIDA;
    private static TipoPantalla pantallaAnterior = TipoPantalla.DESCONOCIDA;

    public static TipoPantalla getPantallaActual() {
        return pantallaActual;
    }

    public static TipoPantalla getPantallaAnterior() {
        return pantallaAnterior;
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

    public static void irAPerfil() {
        pantallaActual = TipoPantalla.PERFIL;
        cambiarEscena("/com/tfg/analizador/VistaPerfil.fxml", "TFG - Gestión de Cuenta");
    }

    // Método clásico para un protocolo nuevo en blanco
    public static void irAAnalizador() {
        cargarAnalizador(null, null);
    }

    // Sobrecarga para acceder al analizador pasando un archivo importado.
    public static void irAAnalizadorConArchivo(String contenido, File archivo) {
        cargarAnalizador(contenido, archivo);
    }

    // Si recibe contenido, lo inyecta directamente tras crear la vista.
    private static void cargarAnalizador(String contenido, File archivo) {
        String rutaFXML = "/com/tfg/analizador/VistaAnalizador.fxml";
        URL url = GestorVistas.class.getResource(rutaFXML);
        
        if (url == null) {
            System.err.println("ERROR CRÍTICO: No se encuentra el archivo FXML en: " + rutaFXML);
            return;
        }

        try {
            pantallaActual = TipoPantalla.ANALIZADOR;
            
            // Carga manual del FXML
            FXMLLoader loader = new FXMLLoader(url);
            Parent root = loader.load();

            // Obtenemos los controladores
            ControladorAnalisis controladorAnalisis = loader.getController();
            
            // Si venimos de la función "Importar Protocolo", inyectamos el archivo en el editor
            if (contenido != null && archivo != null) {
                controladorAnalisis.cargarTextoEnEditor(contenido, archivo);
            }
            
            // Asumiendo que en tu VistaAnalizador.fxml tienes: <fx:include fx:id="menuSuperior" source="MenuSuperior.fxml" />
            ControladorMenu controladorMenu = (ControladorMenu) loader.getNamespace().get("menuSuperiorController");
            
            if (controladorMenu != null) {
                controladorMenu.setControladorAnalisis(controladorAnalisis);
            }

            // Cambiamos la escena
            Scene escena = new Scene(root);
            escenarioPrincipal.setTitle("TFG - Analizador de Protocolos (Editor)");
            escenarioPrincipal.setScene(escena);
            
        } catch (IOException e) {
            System.err.println("Error al cargar la vista del analizador");
            e.printStackTrace();
        }
    }

    public static void mostrarGuiaUsuario() {
        pantallaAnterior = pantallaActual; // <-- Memorizamos de dónde venimos
        pantallaActual = TipoPantalla.GUIA;
        cambiarEscena("/com/tfg/analizador/VistaGuia.fxml", "TFG - Guía de Usuario");
    }

    public static void irARecuperarPass() {
        pantallaActual = TipoPantalla.RECUPERAR_PASS;
        cambiarEscena("/com/tfg/analizador/VistaRecuperarPass.fxml", "TFG - Recuperar Contraseña");
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