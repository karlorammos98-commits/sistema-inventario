-- Agrega un contador por categoría para generar códigos secuenciales.
-- Ejecutar en la base de datos inventario_local.

ALTER TABLE items
ADD COLUMN IF NOT EXISTS secuencia_categoria INTEGER NULL;

