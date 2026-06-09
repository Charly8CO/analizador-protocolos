package com.tfg.analizador.persistencia;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import com.tfg.analizador.modelo.Protocolo;
import com.tfg.analizador.modelo.Usuario;
import com.tfg.analizador.modelo.Vulnerabilidad;

public class GestorBBDD {

    private static Connection conexion = null;
    
    // URL de la base de datos
    private static final String URL = "jdbc:sqlite:analisis.db?foreign_keys=on";

    // Establecer conexión y devolverla para que se pueda usar
    public static Connection getConexion() throws SQLException {
        if (conexion == null || conexion.isClosed()) {
            conexion = DriverManager.getConnection(URL);
            System.out.println("Se ha establecido conexión con la base de datos");
        }
        return conexion;
    }

    public static void cerrarConexion() {
        try {
            if (conexion != null && !conexion.isClosed()) {
                conexion.close();
                System.out.println("Conexión con la base de datos cerrada.");
            }
        } catch (SQLException e) {
            System.err.println("Se ha producido un error al cerrar la conexión: " + e.getMessage());
        }
    }

    public static void inicializarTablas() {
        // tabla USUARIO
        String sqlUsuario = "CREATE TABLE IF NOT EXISTS USUARIO ("
                + "id_usuario INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "nombre_usuario TEXT UNIQUE NOT NULL, "
                + "hash_contra TEXT NOT NULL"
                + ");";

        // Tabla PROTOCOLO
        String sqlProtocolo = "CREATE TABLE IF NOT EXISTS PROTOCOLO ("
                + "id_protocolo INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "id_usuario INTEGER NOT NULL, "
                + "nombre_protocolo TEXT NOT NULL, "
                + "fecha_analisis TEXT, "
                + "es_seguro INTEGER, "
                + "Path TEXT NOT NULL, "
                + "FOREIGN KEY (id_usuario) REFERENCES USUARIO(id_usuario) ON DELETE CASCADE"
                + ");";

        // Tabla VULNERABILIDAD
        String sqlVulnerabilidad = "CREATE TABLE IF NOT EXISTS VULNERABILIDAD ("
                + "id_vulnerabilidad INTEGER PRIMARY KEY AUTOINCREMENT, "
                + "id_protocolo INTEGER NOT NULL, "
                + "nombre_vulnerabilidad TEXT NOT NULL, "
                + "tipo_vulnerabilidad TEXT NOT NULL, "
                + "linea INTEGER NOT NULL, "
                + "descripcion TEXT, "
                + "FOREIGN KEY (id_protocolo) REFERENCES PROTOCOLO(id_protocolo) ON DELETE CASCADE"
                + ");";

        try (java.sql.Statement stmt = getConexion().createStatement()) {
            stmt.execute(sqlUsuario);
            stmt.execute(sqlProtocolo);
            stmt.execute(sqlVulnerabilidad);
            System.out.println("Base de datos inicializada: Estructura de tablas comprobada.");
        } catch (SQLException e) {
            System.err.println("Error crítico al inicializar las tablas: " + e.getMessage());
        }
    }

    public void guardarUsuario(Usuario us) throws SQLException{
        // Los ? ? sirven para indicar que los datos necesarios para la consulta serán enviados luego
        // Evita ataques de inyección
        String sql = "INSERT INTO USUARIO (nombre_usuario, hash_contra) VALUES (?, ?)";
        
        // Abrimos el canal de la consulta 
        // Al hacerlo con el try hacemos que se cierre al terminar		
        try (java.sql.PreparedStatement stmt = getConexion().prepareStatement(sql)) {
            // Pasamos los datos reales en vez de las  1 = primer ? y 2 = segundo ?
            stmt.setString(1, us.getNombreUsuario());
            stmt.setString(2, us.getHashPass());
            // actualizamos
            stmt.executeUpdate();
            System.out.println("Usuario guardado con éxito");
        }
    }

    public Usuario obtenerUsuarioEmail(String email) throws SQLException{
        String sql = "SELECT * FROM USUARIO WHERE nombre_usuario = ?";
        try(java.sql.PreparedStatement stmt = getConexion().prepareStatement(sql)){
            stmt.setString(1, email);
            try(java.sql.ResultSet rs = stmt.executeQuery()){
                if (rs.next()) {
                    Usuario u = new Usuario();
                    u.setIdUsuario(rs.getInt("id_usuario"));
                    u.setNombreUsuario(rs.getString("nombre_usuario"));
                    u.setHashPass(rs.getString("hash_contra"));
                    return u;
                }
            }
        }
        // Cuando el usuario no existe
        return null;
    }

    // Inserta el registro de un archivo de protocolo en la base de datos.
    public static int insertarProtocolo(int idUsuario, String nombreArchivo, String rutaAbsoluta) {
        String sql = "INSERT INTO PROTOCOLO (id_usuario, nombre_protocolo, Path, fecha_analisis) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";

        // Usamos Statement.RETURN_GENERATED_KEYS para poder recuperar la Primary Key
        try (Connection conn = getConexion(); 
             PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            
            pstmt.setInt(1, idUsuario);
            pstmt.setString(2, nombreArchivo);
            pstmt.setString(3, rutaAbsoluta);
            
            pstmt.executeUpdate();
            
            // Recuperamos el ID recién creado para poder atarle las vulnerabilidades después
            try (ResultSet rs = pstmt.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getInt(1); 
                }
            }
            
        } catch (SQLException e) {
            System.err.println("Error al insertar el protocolo en SQLite: " + e.getMessage());
        }
        return -1; // Retorna -1 si hubo fallo
    }

    // Busca si un protocolo con el mismo nombre ya existe para el usuario
    public static int obtenerIdProtocoloPorNombre(int idUsuario, String nombreProtocolo) {
        String sql = "SELECT id_protocolo FROM PROTOCOLO WHERE id_usuario = ? AND nombre_protocolo = ?";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idUsuario);
            pstmt.setString(2, nombreProtocolo);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("id_protocolo");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error al verificar existencia del protocolo: " + e.getMessage());
        }
        return -1;
    }

    // Método específico para el botón de Guardar simple que actualiza el Path sin tocar vulnerabilidades
    public static boolean registrarGuardadoManual(int idUsuario, String nombreArchivo, String rutaAbsoluta) {
        int idExistente = obtenerIdProtocoloPorNombre(idUsuario, nombreArchivo);
        
        if (idExistente != -1) {
            String sql = "UPDATE PROTOCOLO SET Path = ?, fecha_analisis = CURRENT_TIMESTAMP WHERE id_protocolo = ?";
            try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, rutaAbsoluta);
                pstmt.setInt(2, idExistente);
                pstmt.executeUpdate();
                return true;
            } catch (SQLException e) {
                System.err.println("Error al actualizar la ruta del protocolo: " + e.getMessage());
                return false;
            }
        } else {
            return insertarProtocolo(idUsuario, nombreArchivo, rutaAbsoluta) != -1;
        }
    }

    // Guarda el análisis completo: actualiza el protocolo (incluyendo su Path) si ya existe o crea uno nuevo si no.
    public boolean guardarHistorial(Usuario u, Protocolo p, String rutaAbsoluta) {
        // Comprobamos si el protocolo con ese mismo nombre ya está en la base de datos
        int idExistente = obtenerIdProtocoloPorNombre(u.getIdUsuario(), p.getNombreProtocolo());
        
        if (idExistente != -1) {
            // Si ya existe actualizamos
            p.setIdProtocolo(idExistente); 
            
            // Actualizamos también el Path por si el archivo ha sido importado desde otra ubicación
            String sqlUpdate = "UPDATE PROTOCOLO SET es_seguro = ?, fecha_analisis = CURRENT_TIMESTAMP, Path = ? WHERE id_protocolo = ?";
            try (Connection conn = getConexion(); PreparedStatement pstmtUpdate = conn.prepareStatement(sqlUpdate)) {
                pstmtUpdate.setInt(1, p.isSeguro() ? 1 : 0);
                pstmtUpdate.setString(2, rutaAbsoluta);
                pstmtUpdate.setInt(3, idExistente);
                pstmtUpdate.executeUpdate();
            } catch (SQLException e) {
                System.err.println("Error al actualizar el protocolo existente: " + e.getMessage());
                return false;
            }
            
            // Eliminamos las vulnerabilidades del análisis anterior para limpiar el historial de este archivo
            String sqlDeleteVulns = "DELETE FROM VULNERABILIDAD WHERE id_protocolo = ?";
            try (Connection conn = getConexion(); PreparedStatement pstmtDelete = conn.prepareStatement(sqlDeleteVulns)) {
                pstmtDelete.setInt(1, idExistente);
                pstmtDelete.executeUpdate();
            } catch (SQLException e) {
                System.err.println("Error al limpiar las vulnerabilidades obsoletas: " + e.getMessage());
            }
            
            // Insertamos el nuevo set de fallos lógicos detectados en lote
            insertarVulnerabilidadesLote(idExistente, p.getVulnerabilidades());
            return true;
            
        } else {
            // Si es l aprimera vez insertamos normalmente
            int idGenerado = insertarProtocolo(u.getIdUsuario(), p.getNombreProtocolo(), rutaAbsoluta);
            
            if (idGenerado != -1) {
                p.setIdProtocolo(idGenerado); 
                
                String sqlUpdate = "UPDATE PROTOCOLO SET es_seguro = ? WHERE id_protocolo = ?";
                try (Connection conn = getConexion(); PreparedStatement pstmtUpdate = conn.prepareStatement(sqlUpdate)) {
                    pstmtUpdate.setInt(1, p.isSeguro() ? 1 : 0);
                    pstmtUpdate.setInt(2, idGenerado);
                    pstmtUpdate.executeUpdate();
                } catch (SQLException e) {
                    System.err.println("Error al actualizar seguridad: " + e.getMessage());
                }
                
                // Insertar todas las vulnerabilidades vinculadas a ese protocolo
                insertarVulnerabilidadesLote(idGenerado, p.getVulnerabilidades());
                return true;
            }
        }
        return false;
    }

    // Encapsular la inserción limpia de vulnerabilidades en lote
    private void insertarVulnerabilidadesLote(int idProtocolo, List<Vulnerabilidad> vulnerabilidades) {
        if (vulnerabilidades != null && !vulnerabilidades.isEmpty()) {
            String sqlVuln = "INSERT INTO VULNERABILIDAD (id_protocolo, nombre_vulnerabilidad, tipo_vulnerabilidad, linea, descripcion) VALUES (?, ?, ?, ?, ?)";
            try (Connection conn = getConexion(); PreparedStatement pstmtVuln = conn.prepareStatement(sqlVuln)) {
                
                for (Vulnerabilidad v : vulnerabilidades) {
                    pstmtVuln.setInt(1, idProtocolo);
                    pstmtVuln.setString(2, v.getTipoAtaque());
                    pstmtVuln.setString(3, "Lógica");
                    pstmtVuln.setInt(4, v.getLineaAfectada());
                    pstmtVuln.setString(5, v.getDescripcion());
                    pstmtVuln.addBatch();
                }
                pstmtVuln.executeBatch(); 
            } catch (SQLException e) {
                System.err.println("Error al insertar las vulnerabilidades en lote: " + e.getMessage());
            }
        }
    }

    // Carga todos los metadatos de los protocolos de un usuario para rellenar el Dashboard.
    public List<Protocolo> cargarProtocolos(int idusuario) {
        List<Protocolo> lista = new ArrayList<>();
        String sql = "SELECT * FROM PROTOCOLO WHERE id_usuario = ? ORDER BY fecha_analisis DESC";
        
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idusuario);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Protocolo p = new Protocolo(rs.getString("nombre_protocolo"));
                    p.setIdProtocolo(rs.getInt("id_protocolo"));
                    p.setRutaArchivo(rs.getString("Path")); // GUARDAMOS LA RUTA
                    
                    int seguroNum = rs.getInt("es_seguro");
                    if (!rs.wasNull()) {
                        p.setSeguro(seguroNum == 1);
                    }
                    lista.add(p);
                }
            }
        } catch (SQLException e) {
            System.err.println("Error al cargar protocolos del historial: " + e.getMessage());
        }
        return lista;
    }

    public boolean renombrarProtocolo(int idProtocolo, String nuevoNombre, String nuevaRuta) {
        String sql = "UPDATE PROTOCOLO SET nombre_protocolo = ?, Path = ? WHERE id_protocolo = ?";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, nuevoNombre);
            pstmt.setString(2, nuevaRuta);
            pstmt.setInt(3, idProtocolo);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error al renombrar el protocolo: " + e.getMessage());
            return false;
        }
    }

    public boolean actualizarPassword(int idUsuario, String nuevoHash) {
        String sql = "UPDATE USUARIO SET hash_contra = ? WHERE id_usuario = ?";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, nuevoHash);
            pstmt.setInt(2, idUsuario);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error al actualizar contraseña: " + e.getMessage());
            return false;
        }
    }

    public boolean eliminarUsuario(int idUsuario) {
        String sql = "DELETE FROM USUARIO WHERE id_usuario = ?";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idUsuario);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error al eliminar usuario: " + e.getMessage());
            return false;
        }
    }

    public int obtenerTotalProtocolosSeguros(int idUsuario) {
        String sql = "SELECT COUNT(*) FROM PROTOCOLO WHERE id_usuario = ? AND es_seguro = 1";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idUsuario);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            System.err.println("Error al contar protocolos seguros: " + e.getMessage());
        }
        return 0;
    }

    public int obtenerTotalVulnerabilidades(int idUsuario) {
        String sql = "SELECT COUNT(v.id_vulnerabilidad) FROM VULNERABILIDAD v " +
                     "INNER JOIN PROTOCOLO p ON v.id_protocolo = p.id_protocolo WHERE p.id_usuario = ?";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idUsuario);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            System.err.println("Error al contar vulnerabilidades: " + e.getMessage());
        }
        return 0;
    }

    // Devuelve un mapa con el conteo de vulnerabilidades agrupadas por su nombre/tipo
    public java.util.Map<String, Integer> obtenerDistribucionVulnerabilidades(int idUsuario) {
        java.util.Map<String, Integer> distribucion = new java.util.HashMap<>();
        String sql = "SELECT v.nombre_vulnerabilidad, COUNT(*) as cantidad FROM VULNERABILIDAD v " +
                     "INNER JOIN PROTOCOLO p ON v.id_protocolo = p.id_protocolo " +
                     "WHERE p.id_usuario = ? GROUP BY v.nombre_vulnerabilidad";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idUsuario);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    distribucion.put(rs.getString("nombre_vulnerabilidad"), rs.getInt("cantidad"));
                }
            }
        } catch (SQLException e) {
            System.err.println("Error al agrupar vulnerabilidades: " + e.getMessage());
        }
        return distribucion;
    }

    // Borra un protocolo del historial. 
    public boolean eliminarProtocolo(int idprotocolo) {
        String sql = "DELETE FROM PROTOCOLO WHERE id_protocolo = ?";
        try (Connection conn = getConexion(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, idprotocolo);
            int filasModificadas = pstmt.executeUpdate();
            return filasModificadas > 0;
        } catch (SQLException e) {
            System.err.println("Error al borrar protocolo: " + e.getMessage());
            return false;
        }
    }

    public Usuario verificarCredenciales(String nombre, String hashPass) {
        // La validación de credenciales (BCrypt) ya se hace de manera superior y más segura
        // en GestorUsuarios.autenticarUsuario(). Dejo esto comentado para no causar duplicidad.
        throw new UnsupportedOperationException("Operación delegada a GestorUsuarios.autenticarUsuario()");
    }
}