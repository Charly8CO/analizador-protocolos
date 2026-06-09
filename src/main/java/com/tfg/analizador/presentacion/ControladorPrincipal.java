package com.tfg.analizador.presentacion;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.persistencia.GestorBBDD;
import com.tfg.analizador.util.GestorDialogos;
import com.tfg.analizador.util.GestorVistas;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.chart.PieChart;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;

public class ControladorPrincipal {

    @FXML
    private TableView<Protocolo> tablaProtocolos;
    @FXML
    private TableColumn<Protocolo, String> colNombre;
    @FXML
    private TableColumn<Protocolo, Void> colAcciones;

    // Etiquetas de estadísticas
    @FXML
    private Label lblProtocolosSeguros;
    @FXML
    private Label lblTotalVulnerabilidades;
    @FXML
    private Label lblTotalAnalisis;

    // Gráficos
    @FXML
    private PieChart graficoSeguridad;
    @FXML
    private PieChart graficoTiposVuln;

    private GestorBBDD gestorBD;
    private Usuario usuarioActual;

    @FXML
    public void initialize() {
        this.usuarioActual = GestorSesion.getInstancia().getUsuarioActivo();
        this.gestorBD = new GestorBBDD();
        
        if (usuarioActual != null) {
            System.out.println("Panel de Control cargado para: " + usuarioActual.getNombreUsuario());
            
            configurarTabla();
            cargarDatosDashboard();
        }
    }

    private void configurarTabla() {
        // Enlaza la columna de nombre con el atributo nombreProtocolo del modelo
        colNombre.setCellValueFactory(new PropertyValueFactory<>("nombreProtocolo"));

        // Crea una fábrica de celdas a medida para inyectar 3 botones por cada fila
        colAcciones.setCellFactory(param -> new TableCell<>() {
            private final Button btnAbrir = new Button("Consultar");
            private final Button btnEditar = new Button("Renombrar");
            private final Button btnEliminar = new Button("Eliminar");
            private final HBox pane = new HBox(10, btnAbrir, btnEditar, btnEliminar);

            {
                // Estilos opcionales (Asegúrate de que existan en tu CSS o quítalos)
                btnAbrir.setStyle("-fx-background-color: #3498DB; -fx-text-fill: white;");
                btnEditar.setStyle("-fx-background-color: #F39C12; -fx-text-fill: white;");
                btnEliminar.setStyle("-fx-background-color: #E74C3C; -fx-text-fill: white;");

                // Abrir 
                btnAbrir.setOnAction(e -> {
                    Protocolo p = getTableView().getItems().get(getIndex());
                    abrirProtocolo(p);
                });

                // Renombrar
                btnEditar.setOnAction(e -> {
                    Protocolo p = getTableView().getItems().get(getIndex());
                    renombrarProtocolo(p);
                });

                // Eliminar
                btnEliminar.setOnAction(e -> {
                    Protocolo p = getTableView().getItems().get(getIndex());
                    eliminarProtocolo(p);
                });
            }

            @Override
            protected void updateItem(Void item, boolean empty) {
                super.updateItem(item, empty);
                if (empty) {
                    setGraphic(null);
                } else {
                    setGraphic(pane);
                }
            }
        });
    }

    // Refresca todo el contenido visual leyendo directamente de la BBDD
    private void cargarDatosDashboard() {
        int id = usuarioActual.getIdUsuario();

        // Cargar lista de protocolos en la tabla
        List<Protocolo> historial = gestorBD.cargarProtocolos(id);
        ObservableList<Protocolo> datosTabla = FXCollections.observableArrayList(historial);
        tablaProtocolos.setItems(datosTabla);

        // Cargar textos de estadísticas
        int seguros = gestorBD.obtenerTotalProtocolosSeguros(id);
        int vulnerabilidades = gestorBD.obtenerTotalVulnerabilidades(id);
        int totalProtocolos = historial.size();

        lblProtocolosSeguros.setText("Protocolos seguros detectados: " + seguros);
        lblTotalVulnerabilidades.setText("Vulnerabilidades históricas: " + vulnerabilidades);
        lblTotalAnalisis.setText("Total de archivos analizados: " + totalProtocolos);

        // Cargar Gráfico de Seguridad
        ObservableList<PieChart.Data> datosSeguridad = FXCollections.observableArrayList(
            new PieChart.Data("Seguros (" + seguros + ")", seguros),
            new PieChart.Data("Inseguros (" + (totalProtocolos - seguros) + ")", totalProtocolos - seguros)
        );
        graficoSeguridad.setData(datosSeguridad);
        graficoSeguridad.setTitle("Ratio de Seguridad");

        // 4. Cargar Gráfico de Vulnerabilidades
        Map<String, Integer> distribucion = gestorBD.obtenerDistribucionVulnerabilidades(id);
        ObservableList<PieChart.Data> datosVuln = FXCollections.observableArrayList();
        
        for (Map.Entry<String, Integer> entrada : distribucion.entrySet()) {
            datosVuln.add(new PieChart.Data(entrada.getKey(), entrada.getValue()));
        }
        graficoTiposVuln.setData(datosVuln);
        graficoTiposVuln.setTitle("Tipos de Fallos Frecuentes");
    }

    private void abrirProtocolo(Protocolo p) {
        String ruta = p.getRutaArchivo();
        if (ruta == null || ruta.isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Sin ruta", "No se guardó ninguna ruta física para este protocolo.", "Aceptar");
            return;
        }

        File archivo = new File(ruta);
        if (!archivo.exists()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Archivo no encontrado", "El archivo físico ya no está en la ruta guardada (" + ruta + "). Se ha movido o borrado.", "Entendido");
            return;
        }

        try {
            // Leemos y mandamos el archivo al analizador a través de GestorVistas
            String contenido = Files.readString(archivo.toPath());
            GestorVistas.irAAnalizadorConArchivo(contenido, archivo);
        } catch (Exception ex) {
            GestorDialogos.mostrarConfirmacionEstandar("Error", "Error al leer", "No se pudo leer el archivo: " + ex.getMessage(), "Aceptar");
        }
    }

    private void renombrarProtocolo(Protocolo p) {
        TextInputDialog dialog = new TextInputDialog(p.getNombreProtocolo());
        dialog.setTitle("Renombrar Protocolo");
        dialog.setHeaderText("Cambiar nombre del archivo e historial");
        dialog.setContentText("Nuevo nombre (sin extensión):");

        Optional<String> result = dialog.showAndWait();
        result.ifPresent(nuevoNombre -> {
            String nombreLimpio = nuevoNombre.trim();
            if (!nombreLimpio.isEmpty() && !nombreLimpio.equals(p.getNombreProtocolo())) {
                
                File archivoAntiguo = new File(p.getRutaArchivo());
                if (!archivoAntiguo.exists()) {
                    GestorDialogos.mostrarConfirmacionEstandar("Error", "Archivo no encontrado", "No se puede renombrar porque el archivo original ya no está en la ruta.", "Aceptar");
                    return;
                }

                // Construimos la nueva ruta manteniendo el directorio y forzando la extensión .prot
                String nombreConExtension = nombreLimpio.endsWith(".prot") ? nombreLimpio : nombreLimpio + ".prot";
                String nuevaRuta = archivoAntiguo.getParent() + File.separator + nombreConExtension;
                File archivoNuevo = new File(nuevaRuta);

                if (archivoNuevo.exists()) {
                    GestorDialogos.mostrarConfirmacionEstandar("Error", "Nombre duplicado", "Ya existe un archivo con ese nombre en la carpeta.", "Aceptar");
                    return;
                }

                // Renombrar archivo físico
                if (archivoAntiguo.renameTo(archivoNuevo)) {
                    // Si el SO lo renombra, actualizamos la base de datos
                    boolean exito = gestorBD.renombrarProtocolo(p.getIdProtocolo(), nombreLimpio, nuevaRuta);
                    if (exito) {
                        p.setNombreProtocolo(nombreLimpio);
                        p.setRutaArchivo(nuevaRuta);
                        tablaProtocolos.refresh(); // Actualizamos la vista
                    } else {
                        // Si falla la BD, revertimos el nombre del archivo para no corromper estados
                        archivoNuevo.renameTo(archivoAntiguo);
                        GestorDialogos.mostrarConfirmacionEstandar("Error BD", "Fallo al renombrar", "No se pudo actualizar la base de datos.", "Aceptar");
                    }
                } else {
                    GestorDialogos.mostrarConfirmacionEstandar("Error SO", "No se pudo renombrar", "El sistema operativo bloqueó el renombrado (puede que el archivo esté abierto en otro programa).", "Aceptar");
                }
            }
        });
    }

    private void eliminarProtocolo(Protocolo p) {
        boolean confirmar = GestorDialogos.mostrarConfirmacionEstandar(
            "Eliminar Registro", 
            "¿Borrar " + p.getNombreProtocolo() + "?", 
            "Se eliminará el protocolo y sus vulnerabilidades del historial. El archivo físico NO será borrado.", 
            "Eliminar"
        );

        if (confirmar) {
            if (gestorBD.eliminarProtocolo(p.getIdProtocolo())) {
                cargarDatosDashboard(); // Recargamos para que las estadísticas y gráficas se actualicen
            } else {
                GestorDialogos.mostrarConfirmacionEstandar("Error", "No se pudo borrar", "Hubo un error en la base de datos.", "Aceptar");
            }
        }
    }
}