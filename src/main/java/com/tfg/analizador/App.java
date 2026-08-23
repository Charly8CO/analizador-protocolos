package com.tfg.analizador;

import com.tfg.analizador.persistencia.GestorBBDD;
import com.tfg.analizador.util.GestorVistas;

import javafx.application.Application;
import javafx.stage.Stage;
public class App extends Application{

    //al usar javafx en el main es mejor solo el incluir el launch para evitar posibles bloqueos
    public static void main(String[] args) {
        //sirve para lanzar la interfaz grafica (y el args son los argumentos de la linea de comandos)
        launch(args);
    }

    @Override
    public void start(Stage escenarioBase) throws Exception {

        // Inicializamos la base de datos antes de mostrar nada
        GestorBBDD.inicializarTablas();

        GestorVistas.setEscenarioPrincipal(escenarioBase);

        //Cargamos el login
        GestorVistas.irALogin();

        escenarioBase.setResizable(true);
        escenarioBase.setMinWidth(1024);
        escenarioBase.setMinHeight(700);
        escenarioBase.setOnCloseRequest(event -> GestorBBDD.cerrarConexion());
        escenarioBase.show();

    }
}