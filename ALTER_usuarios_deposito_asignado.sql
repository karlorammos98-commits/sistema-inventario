-- Agrega el depósito asignado a los usuarios.
-- Ejecutar en la base de datos inventario_local.

ALTER TABLE usuarios
ADD COLUMN IF NOT EXISTS deposito_asignado_id INTEGER NULL;

ALTER TABLE usuarios
ADD CONSTRAINT IF NOT EXISTS usuarios_deposito_asignado_fk
FOREIGN KEY (deposito_asignado_id) REFERENCES depositos(id);

