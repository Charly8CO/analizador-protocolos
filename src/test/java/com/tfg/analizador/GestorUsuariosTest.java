package com.tfg.analizador;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import com.tfg.analizador.modelo.Usuario;

public class GestorUsuariosTest {

    @Test
    void testGeneracionSaltoBCryptYModeloUsuario() {
        String passPlana = "ClaveSuperSegura123";
        
        // Generamos dos hashes diferentes para la misma clave plana
        String hash1 = BCrypt.hashpw(passPlana, BCrypt.gensalt());
        String hash2 = BCrypt.hashpw(passPlana, BCrypt.gensalt());
        
        // Instanciamos el modelo con uno de los hashes
        Usuario usuarioTest = new Usuario("AliceAdmin", hash1);
        
        // 1. Verificamos que el salt garantiza la aleatoriedad
        assertNotEquals(hash1, hash2, "El salt debe garantizar que los hashes varíen.");
        
        // 2. Verificamos que el modelo almacena el hash, no la clave plana
        assertNotEquals(passPlana, usuarioTest.getHashPass(), "El modelo no debe almacenar la clave en texto plano.");
        
        // 3. Verificamos la autenticación exitosa usando el hash del modelo
        assertTrue(BCrypt.checkpw(passPlana, usuarioTest.getHashPass()), "La validación BCrypt debe ser exitosa con la clave correcta.");
    }
}