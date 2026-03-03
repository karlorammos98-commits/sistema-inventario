-- Agrega el usuario que realizó cada movimiento de stock.
-- Ejecutar en la base de datos inventario_local.

ALTER TABLE movimientos
ADD COLUMN IF NOT EXISTS usuario_id INTEGER NULL REFERENCES usuarios(id);

