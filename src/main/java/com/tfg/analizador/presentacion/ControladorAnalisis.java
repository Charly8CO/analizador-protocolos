package com.tfg.analizador.presentacion;

import java.io.File;
import java.util.Optional;

import org.fxmisc.flowless.VirtualizedScrollPane;
import org.fxmisc.richtext.CodeArea;
import org.fxmisc.richtext.LineNumberFactory;

import com.tfg.analizador.logica.GestorSesion;
import com.tfg.analizador.logica.ServicioAnalisis;
import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Vulnerabilidad;
import com.tfg.analizador.persistencia.GestorArchivos;
import com.tfg.analizador.util.GestorDialogos;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.ContextMenu;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.StackPane;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;

public class ControladorAnalisis {

    @FXML
    private StackPane contenedorEditor;

    @FXML
    private ListView<String> listaActores;

    @FXML
    private TableView<Vulnerabilidad> tablaVulnerabilidades;

    @FXML
    private TableColumn<Vulnerabilidad, String> colVulnNombre;

    @FXML
    private TableColumn<Vulnerabilidad, Integer> colVulnLinea;

    @FXML
    private TableColumn<Vulnerabilidad, String> colVulnDesc;

    private CodeArea editorProtocolo;

    private File archivoActual = null;

    private Protocolo ultimoProtocoloAnalizado = null;

    @FXML
    public void initialize() {
        // Establecer KDC por defecto
        listaActores.getItems().add("KDC");

        // Menú contextual para poder eliminar actores
        ContextMenu menuActores = new ContextMenu();
        MenuItem eliminarActor = new MenuItem("Eliminar Actor");
        eliminarActor.setOnAction(e -> {
            String seleccionado = listaActores.getSelectionModel().getSelectedItem();
            if (seleccionado != null) {
                listaActores.getItems().remove(seleccionado);
            }
        });
        menuActores.getItems().add(eliminarActor);
        listaActores.setContextMenu(menuActores);

        // Instanciamos el editor avanzado
        editorProtocolo = new CodeArea();
        editorProtocolo.setParagraphGraphicFactory(LineNumberFactory.get(editorProtocolo));

        // Esto sirve para evitar apelotonamientos
        VirtualizedScrollPane<CodeArea> scrollEditor = new VirtualizedScrollPane<>(editorProtocolo);

        // Inyectamos el panel de scroll
        contenedorEditor.getChildren().add(scrollEditor);

        colVulnNombre.setCellValueFactory(new PropertyValueFactory<>("tipoAtaque"));
        colVulnLinea.setCellValueFactory(new PropertyValueFactory<>("lineaAfectada"));
        colVulnDesc.setCellValueFactory(new PropertyValueFactory<>("descripcion"));

        // Envolvemos el texto de la descripción para que salte de línea automáticamente
        colVulnDesc.setCellFactory(tc -> {
            TableCell<Vulnerabilidad, String> cell = new TableCell<>() {
                private Text text = new Text();

                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setGraphic(null);
                    } else {
                        text.setText(item);
                        // Restamos unos píxeles de padding para que no se pegue al borde
                        text.wrappingWidthProperty().bind(colVulnDesc.widthProperty().subtract(10));
                        setGraphic(text);
                    }
                }
            };
            return cell;
        });

        colVulnNombre.setCellFactory(tc -> {
            TableCell<Vulnerabilidad, String> cell = new TableCell<>() {
                private Text text = new Text();

                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setGraphic(null);
                    } else {
                        text.setText(item);
                        text.wrappingWidthProperty().bind(colVulnNombre.widthProperty().subtract(10));
                        setGraphic(text);
                    }
                }
            };
            return cell;
        });
    }

    // Permite que otros controladores inyecten texto importado
    public void cargarTextoEnEditor(String texto, File archivoAsociado) {
        editorProtocolo.replaceText(texto);
        this.archivoActual = archivoAsociado;
        this.ultimoProtocoloAnalizado = null; // Reseteamos análisis al cargar uno nuevo
        tablaVulnerabilidades.getItems().clear();
    }

    @FXML
    void handleNuevoActor(ActionEvent event) {
        // Abre la ventana de crear nuevo actor
        Optional<String> resultado = GestorDialogos.solicitarNombreActor();

        // Si se pulsa añadir tras escribir un nuevo actor
        resultado.ifPresent(nombre -> {
            if (nombre.isEmpty()) {
                GestorDialogos.mostrarConfirmacionEstandar("Advertencia", "Campo vacío",
                        "El nombre del actor no puede estar en blanco.", "Aceptar");
            } else if (listaActores.getItems().contains(nombre)) {
                GestorDialogos.mostrarConfirmacionEstandar("Advertencia", "Actor duplicado",
                        "El actor '" + nombre + "' ya existe en la lista.", "Aceptar");
            } else {
                listaActores.getItems().add(nombre);
            }
        });
    }

    @FXML
    void handleValidarSintaxis(ActionEvent event) {
        String textoUsuario = editorProtocolo.getText();

        if (textoUsuario.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío",
                    "Escribe un protocolo antes de validar.", "Aceptar");
            return;
        }

        try {
            ServicioAnalisis servicio = new ServicioAnalisis();
            servicio.validarSintaxisSolo(textoUsuario); // Lanza excepción si la estructura falla

            GestorDialogos.mostrarConfirmacionEstandar("Validación", "Sintaxis Correcta",
                    "La estructura del protocolo es válida. Puedes proceder a analizarlo.", "Aceptar");
        } catch (Exception e) {
            GestorDialogos.mostrarConfirmacionEstandar("Error de Sintaxis", "Estructura incorrecta", e.getMessage(),
                    "Aceptar");
        }
    }

    @FXML
    void handleAnalizarProtocolo(ActionEvent event) {
        String textoUsuario = editorProtocolo.getText();

        if (textoUsuario.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío",
                    "Escribe un protocolo antes de analizar.", "Aceptar");
            return;
        }

        File archivo = this.archivoActual;

        // Comprobación de integridad del archivo para evitar pérdida de trabajo en
        // memoria
        if (archivo != null && !archivo.exists()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Archivo original no encontrado",
                    "El archivo de este análisis ha sido borrado o movido de su ubicación original. Para no perder tu progreso, deberás guardarlo en una nueva ruta.",
                    "Entendido");
            archivo = null; // Esto fuerza la apertura del FileChooser
        }

        if (archivo == null) {
            FileChooser selector = new FileChooser();
            selector.setTitle("Guardar Protocolo para Analizar");
            selector.getExtensionFilters()
                    .add(new FileChooser.ExtensionFilter("Archivos de Protocolo (*.prot)", "*.prot"));

            archivo = selector.showSaveDialog(contenedorEditor.getScene().getWindow());

            if (archivo == null) {
                GestorDialogos.mostrarConfirmacionEstandar(
                        "Análisis Cancelado",
                        "Guardado Obligatorio",
                        "Debes guardar el archivo en tu equipo para poder realizar el análisis y registrar los fallos en el historial.",
                        "Aceptar");
                return;
            }
            this.archivoActual = archivo;
        }

        try {
            ServicioAnalisis servicio = new ServicioAnalisis();

            // Antes de procesar el protocolo, forzamos la sobreescritura física
            // del archivo para así guardar lo actualizado.
            servicio.guardarProtocolo(archivo, textoUsuario);

            // Delegamos la validación, compilación, análisis y registro BBDD condicional
            Protocolo protocoloProcesado = servicio.procesarYGuardarProtocolo(textoUsuario, archivo);

            // Guardamos el objeto en memoria para el PDF
            this.ultimoProtocoloAnalizado = protocoloProcesado;

            actualizarListaActores(protocoloProcesado);
            ObservableList<Vulnerabilidad> data = FXCollections
                    .observableArrayList(protocoloProcesado.getVulnerabilidades());
            tablaVulnerabilidades.setItems(data);

            if (protocoloProcesado.isSeguro()) {
                GestorDialogos.mostrarConfirmacionEstandar("Análisis Finalizado", "Protocolo Seguro",
                        "El documento se ha procesado. No se han detectado fallos lógicos. El diseño es robusto.",
                        "Aceptar");
            } else {
                GestorDialogos.mostrarConfirmacionEstandar(
                        "Análisis Finalizado",
                        "Vulnerabilidades Detectadas",
                        "El documento se ha procesado.\n\nEl motor ha encontrado "
                                + protocoloProcesado.getVulnerabilidades().size()
                                + " brechas de seguridad. Revisa la tabla lateral para más detalles.",
                        "Aceptar");
            }
        } catch (Exception e) {
            GestorDialogos.mostrarConfirmacionEstandar("Error en el Proceso", "No se puede completar", e.getMessage(),
                    "Aceptar");
        }
    }

    // Genera el informe PDF utilizando iText y nuestro GestorArchivos.
    @FXML
    void handleGenerarInforme(ActionEvent event) {
        if (ultimoProtocoloAnalizado == null) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Sin Análisis",
                    "Debes analizar el protocolo antes de poder generar un informe PDF.", "Aceptar");
            return;
        }

        FileChooser selector = new FileChooser();
        selector.setTitle("Guardar Informe PDF");
        selector.getExtensionFilters().add(new FileChooser.ExtensionFilter("Archivos PDF (*.pdf)", "*.pdf"));
        selector.setInitialFileName(ultimoProtocoloAnalizado.getNombreProtocolo() + "_Informe.pdf");

        File archivoPdf = selector.showSaveDialog(contenedorEditor.getScene().getWindow());

        if (archivoPdf != null) {
            try {
                GestorArchivos gestor = new GestorArchivos();
                com.tfg.analizador.modelo.Usuario usuarioActivo = GestorSesion.getInstancia().getUsuarioActivo();
                String textoActual = editorProtocolo.getText();

                // Delegamos la creación del PDF a nuestro gestor
                gestor.generarInformePDF(ultimoProtocoloAnalizado, archivoPdf.getAbsolutePath(), textoActual,
                        usuarioActivo);

                GestorDialogos.mostrarConfirmacionEstandar("Éxito", "Informe Generado",
                        "El informe PDF se ha exportado correctamente.", "Aceptar");
            } catch (Exception e) {
                GestorDialogos.mostrarConfirmacionEstandar("Error", "Error al generar PDF", e.getMessage(), "Aceptar");
            }
        }
    }

    @FXML
    void handleGuardarProtocolo(ActionEvent event) {
        String texto = editorProtocolo.getText();

        if (texto.trim().isEmpty()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Editor vacío", "No hay contenido para guardar.",
                    "Aceptar");
            return;
        }

        File archivoDestino = this.archivoActual;

        // Si el archivo se ha borrado en local, forzamos un Guardar Como
        if (archivoDestino != null && !archivoDestino.exists()) {
            GestorDialogos.mostrarConfirmacionEstandar("Aviso", "Archivo original no encontrado",
                    "El archivo físico ya no se encuentra en su ruta original. Por seguridad, selecciona una nueva ubicación para guardar los cambios.",
                    "Entendido");
            archivoDestino = null;
        }

        // Si es nuevo o el original desapareció, solicitamos ruta
        if (archivoDestino == null) {
            FileChooser selector = new FileChooser();
            selector.setTitle("Guardar Protocolo");
            selector.getExtensionFilters()
                    .add(new FileChooser.ExtensionFilter("Archivos de Protocolo (*.prot)", "*.prot"));

            archivoDestino = selector.showSaveDialog(contenedorEditor.getScene().getWindow());

            // Guardado cancelado por el usuario
            if (archivoDestino == null) {
                return;
            }
        }

        try {
            ServicioAnalisis servicio = new ServicioAnalisis();
            servicio.guardarProtocolo(archivoDestino, texto);

            // Actualizamos la sesión en memoria
            this.archivoActual = archivoDestino;

            GestorDialogos.mostrarConfirmacionEstandar("Éxito", "Protocolo Guardado",
                    "El archivo se ha guardado y actualizado en la base de datos de manera correcta.", "Aceptar");
        } catch (Exception e) {
            GestorDialogos.mostrarConfirmacionEstandar("Error", "Error al guardar", e.getMessage(), "Aceptar");
        }
    }

    @FXML
    void handleLimpiarProtocolo(ActionEvent event) {
        boolean confirmar = GestorDialogos.mostrarConfirmacionEstandar(
                "Confirmar limpieza",
                "¿Vaciar editor?",
                "Se borrará todo el texto actual. ¿Deseas continuar?",
                "Limpiar");

        if (confirmar) {
            editorProtocolo.clear();
            listaActores.getItems().clear();
            listaActores.getItems().add("KDC");
            tablaVulnerabilidades.getItems().clear();
            // Eliminado this.archivoActual = null; para evitar perder el archivo al
            // limpiar.
            this.ultimoProtocoloAnalizado = null;
        }
    }

    private void actualizarListaActores(Protocolo protocolo) {
        if (!listaActores.getItems().contains("KDC")) {
            listaActores.getItems().add("KDC");
        }
        for (com.tfg.analizador.modelo.Agente agente : protocolo.getAgentes()) {
            if (!listaActores.getItems().contains(agente.getNombre())) {
                listaActores.getItems().add(agente.getNombre());
            }
        }
    }
}