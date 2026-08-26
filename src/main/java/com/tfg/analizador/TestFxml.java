package com.tfg.analizador;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
public class TestFxml {
    public static void main(String[] args) {
        Platform.startup(() -> {
            try {
                FXMLLoader.load(TestFxml.class.getResource("/com/tfg/analizador/VistaDashBoard.fxml"));
                System.out.println("LOAD SUCCESSFUL");
            } catch (Exception e) {
                e.printStackTrace();
            }
            Platform.exit();
        });
    }
}
