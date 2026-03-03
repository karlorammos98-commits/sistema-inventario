-- Crea la tabla movimientos para registrar transferencias entre depósitos.
-- Ejecutar en la base de datos inventario_local.

CREATE TABLE IF NOT EXISTS movimientos (
  id SERIAL PRIMARY KEY,
  item_id INTEGER NOT NULL REFERENCES items(id),
  deposito_origen_id INTEGER NOT NULL REFERENCES depositos(id),
  deposito_destino_id INTEGER NOT NULL REFERENCES depositos(id),
  cantidad INTEGER NOT NULL CHECK (cantidad > 0),
  observacion TEXT,
  usuario_id INTEGER NULL REFERENCES usuarios(id)
);
