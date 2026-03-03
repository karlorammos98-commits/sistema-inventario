-- Tabla de depósitos autorizados por usuario.
-- Ejecutar en la base de datos inventario_local.

CREATE TABLE IF NOT EXISTS usuarios_depositos_permitidos (
  usuario_id  INTEGER NOT NULL REFERENCES usuarios(id)   ON DELETE CASCADE,
  deposito_id INTEGER NOT NULL REFERENCES depositos(id) ON DELETE CASCADE,
  PRIMARY KEY (usuario_id, deposito_id)
);

